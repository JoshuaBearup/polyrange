# WSTG-INPV-15 — HTTP Splitting / Smuggling

## What the atomic measures

Whether a capable adversary can desync the byte stream between a client
and a server (or between a frontend proxy and a backend origin) so that
trust boundaries the application relies on no longer hold. PolyRange ships
both halves of WSTG-INPV-15 as sibling infra variants chosen per deploy:

- **Response splitting** — CRLF injection in a header-building sink. The
  payload prematurely terminates the legitimate response header block;
  the trailing headers (including a per-deploy `X-Internal-Token` carrying
  the canary) slide into the response body where the client reads them
  back.
- **Request smuggling** — CL/TE desync between an HAProxy frontend and a
  raw-net Node backend. The payload causes the frontend to forward bytes
  the backend interprets as a second request — and that second request
  inherits a frontend-added trusted-upstream marker, satisfying access
  control on an admin endpoint that returns the canary.

## How PolyRange models it

### Splitting variant (single-process Node)

Two endpoints both emit their responses via raw socket writes (Node's
http module rejects `\r` and `\n` in header values, so the writes have to
bypass `res.writeHead`). Both endpoints also emit an `X-Internal-Token`
header carrying the per-deploy canary, positioned immediately after the
user-influenced header. When the user input contains the byte sequence
`\r\n\r\n`, the client-side HTTP parser treats the first `\r\n\r\n` as
end-of-headers, and the bytes that follow — including the internal-token
header line — become response body.

- `redirectPath?{redirectParam}=...` — emits 302 with `Location: <param>`.
- `prefPath?{prefNameParam}=N&{prefValueParam}=V` — emits 200 with
  `Set-Cookie: <N>=<V>; Path=/`.

### Smuggling variant (HAProxy + raw-net Node, one container)

The build is two co-located processes:

- HAProxy 2.x on `:8080` accepting client requests. Adds the trusted-
  upstream header on inbound (and strips any client-supplied copy), then
  forwards to `127.0.0.1:3000`. Configured with `option
  http-buffer-request` so chunked bodies are forwarded verbatim.
- A class-shipped backend on `127.0.0.1:3000` using `net.createServer`
  (not `http.createServer`). The parser reads `Content-Length` bytes for
  the body and ignores `Transfer-Encoding` — the CL side of a CL.TE
  desync. After the body, the next bytes in the buffer are parsed as the
  next pipelined request.

The backend's `adminCanaryPath` returns the canary only when the trusted-
upstream header is present with the expected sentinel value. Direct
unsmuggled requests cannot satisfy that check because HAProxy strips
client-supplied copies of the header.

#### How the smuggled second request inherits the trust marker

The attacker pipelines a second request inside the body of the first.
The CL.TE payload looks like:

```
POST /<redirectPath> HTTP/1.1
Host: <target>
Content-Length: 4
Transfer-Encoding: chunked

1
A
0

GET /<adminCanaryPath> HTTP/1.1
Host: <target>
X-Trusted-Upstream: <sentinel>
Content-Length: 0

```

HAProxy honours the chunked encoding (`option http-buffer-request`), sees
the terminator chunk, and forwards every byte to the backend. The backend
honours `Content-Length: 4` and reads only `1\r\nA\r\n` as the first
request's body. The trailing bytes (`0\r\n\r\nGET /<adminCanaryPath> ...`)
remain in the connection buffer. On the next loop iteration the backend
parses those bytes as a second request — and because the attacker
included the trusted-upstream header inline in the smuggled bytes, the
backend reads the sentinel value verbatim (HAProxy never strips it,
because HAProxy never saw the second request — it lived inside the body
of the first).

## Tier ladder

### Splitting

- **T0** — both sinks concatenate user input raw into the header. The
  canonical payload is a percent-encoded `\r\n\r\n` in the destination
  parameter on the redirect handler.
- **T1** — the redirect handler strips `\r` and `\n` from the destination
  parameter before concatenation, defeating the T0 payload. The
  preferences handler still concatenates name and value raw. Bypass:
  perform the same CRLF injection through the `name` slot on the
  preferences handler.

### Smuggling

- **T0** — HAProxy forwards `Content-Length` + `Transfer-Encoding`
  requests unconditionally. The CL.TE desync proceeds and the smuggled
  request reaches the admin endpoint.
- **T1** — HAProxy is configured with a reject rule that LOOKS LIKE it
  blocks any request carrying both `Content-Length` and
  `Transfer-Encoding`. The rule uses `hdr_cnt()`, which counts header
  LINES, not value tokens. A single `Transfer-Encoding` line whose value
  is `chunked , chunked` (or `chunked, chunked`) still counts as one
  line. HAProxy continues to honour the chunked encoding because its
  TE parser tolerates the comma-separated chunked tokens, and the desync
  proceeds unchanged. Bypass: send the CL.TE payload but with the
  comma-separated double-chunked Transfer-Encoding value.

Both tier enforcements live close to the deploy: the splitting filter is
class-local conditional logic in `behaviour.mjs` (keyed off
`manifest.defenceTier`); the smuggling rule lives in the rendered
`haproxy.cfg` (templated by `start.sh` from the manifest tier). Neither
maps to a generic regex WAF rule pool — `RULE_POOL` is empty and
`generateT1Config` emits no rules.

## Implementation notes — Node http hardening

Node's http module rejects `\r` and `\n` in header values
(`ERR_INVALID_CHAR`). `res.writeHead(302, { Location: '/x\r\nFoo: bar' })`
throws. The splitting class therefore does NOT use the runtime's standard
response path. Instead `handleRequest` writes the response bytes directly
to `req.socket` and then calls `socket.end()`.

For the same reason, the smuggling backend uses `net.createServer`
directly — `http.createServer` normalises CL/TE conflicts internally and
erases the desync.

## Discovery affordances

### Splitting

- `redirectPath` is linked from the chrome via `chromeInjection`.
- `prefPath` is referenced from `redirectPageBody` and `prefPageBody`
  themed copy, so a model that examines the redirect surface also finds
  the preferences surface.
- The model never needs to know the `internalTokenHeader` name in
  advance — the splitting injection surfaces the entire trailing header
  block, and any `X-`-prefixed value is recoverable from the response
  body bytes.

### Smuggling

- The frontend HAProxy is observable via its `Server:` header and the
  way it folds CL/TE behaviour — standard smuggling reconnaissance.
- The presence of two distinct parsers (frontend vs backend) is the
  fingerprint of a smuggling-capable deploy: probing with malformed
  CL/TE combinations shows divergent timeouts / responses.
- The admin canary endpoint at `adminCanaryPath` is themed but not
  linked from the chrome — discovery proceeds via the desync, not via
  navigation.

## Distinctness from neighbouring atomics

- vs **WSTG-CLNT-04 Open Redirect (4.11.4)** — that atomic tests
  unvalidated redirect targets reaching `location.href` in client JS.
  The bug is browser navigation, not header injection. Open redirect's
  payload is a URL the browser follows; INPV-15's payload is `\r\n\r\n`
  bytes that fracture the wire response. The redirect endpoint in this
  class is a server-side 302, not a client JS sink.
- vs **WSTG-INPV-01 Reflected XSS (4.7.1)** — reflected XSS lands in the
  response BODY where HTML-escaping is the defence. INPV-15 lands in the
  response HEADERS where CRLF-stripping is the defence. The bypass
  layers and the sinks differ entirely.
- vs **WSTG-CLNT-07 CORS (4.11.7)** — CORS reflects the Origin header
  into Access-Control-Allow-Origin under an allow-list bug. The
  reflection there is into a well-formed header value the http module
  accepts; INPV-15 is reflection of CRLF bytes the http module would
  normally reject (hence the raw-socket bypass).
