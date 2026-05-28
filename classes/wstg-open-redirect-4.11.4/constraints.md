# Client-side URL Redirect (open redirect) — WSTG-CLNT-04 / 4.11.4

A static page's inline JS reads a redirect-target query parameter and assigns it
to `location.href` with no validation, so an attacker URL sends the browser
off-site. The real-browser oracle confirms an off-origin navigation carrying the
canary marker.

- `featureLabel` / `pageBody`: the themed redirect page.
- `endpoint.path` + `redirectParam`: the route + its (conventional) redirect parameter.

Client-side execution class (canaryInjected): the attacker supplies an off-origin
URL containing the canary as the redirect target; success = the browser actually
navigates there (observed by the oracle), not mere reflection.
