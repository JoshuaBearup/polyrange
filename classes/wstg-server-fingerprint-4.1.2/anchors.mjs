// Per-deploy stack anchor for WEB SERVER fingerprinting (4.1.2 scope only).
// Server software is a finite real set, so we anchor each deploy to one server
// (crypto-random) to guarantee spread instead of clustering on the model's
// prior (usually Apache). The LLM fills in the realistic version, headers, and
// the authentic body of each default/diagnostic endpoint — this list only
// anchors WHICH server software.
//
// SCOPE: HTTP servers, application servers, and serving infrastructure
// (proxies / caches / gateways) that emit a fingerprintable header AND ship a
// well-known default / diagnostic / admin endpoint that can leak data.
// Frameworks (Rails, Django, Express...) belong to 4.1.8; products / CMS /
// devops UIs (WordPress, Jenkins, Grafana...) belong to 4.1.9.

import crypto from 'node:crypto'

export const STACK_POOL = [
  // ── Traditional HTTP servers ──
  'Apache HTTP Server with mod_status enabled (/server-status, /server-info)',
  'nginx with the stub_status module (/nginx_status, /status, /stub_status)',
  'Microsoft IIS (default /iisstart.htm, exposed web.config)',
  'LiteSpeed Web Server (Server: LiteSpeed, /status real-time stats)',
  'OpenLiteSpeed (Server: LiteSpeed, WebAdmin console artifacts)',
  'lighttpd with mod_status (Server: lighttpd/1.4.x, /server-status)',
  'Caddy (admin API on :2019, /metrics, /config/ JSON)',
  'Tengine — the nginx fork (Server: Tengine, /us upstream status)',
  'Apache Traffic Server (Server: ATS, /_stats endpoint)',
  'H2O server (Server: h2o, /server-status style status handler)',
  'Cherokee (Server: Cherokee, /cherokee admin artifacts)',
  'IBM HTTP Server — Apache-derived (Server: IBM_HTTP_Server, /server-status)',
  'Oracle iPlanet / Sun Java System Web Server (Server: Sun-ONE / iPlanet)',

  // ── Java servlet containers / application servers ──
  'Apache Tomcat (/manager/html, /host-manager/html, /manager/status)',
  'Eclipse Jetty (Server: Jetty(x.y), default Jetty error pages, /__jetty)',
  'WildFly / JBoss (/console, /management, legacy /jmx-console and /web-console)',
  'Oracle WebLogic Server (/console, /bea_wls_internal artifacts)',
  'IBM WebSphere Application Server (/ibm/console, /snoop diagnostic servlet)',
  'GlassFish / Payara (admin console, /common/index.jsf)',
  'Caucho Resin (Server: Resin, /resin-admin)',
  'Undertow (Server: Undertow, default error pages)',
  'Apache Karaf (web console artifacts)',

  // ── Application servers / WSGI / ASGI / Rack runners ──
  'Gunicorn WSGI server (Server: gunicorn/x.y)',
  'uWSGI (Server: uWSGI, /stats stats server)',
  'Werkzeug dev server (Server: Werkzeug/x.y Python/3.x, interactive /console debugger when DEBUG on)',
  'Waitress WSGI server (Server: waitress)',
  'Uvicorn ASGI server (Server: uvicorn)',
  'Hypercorn ASGI server (Server: hypercorn)',
  'Daphne ASGI server (Server: daphne)',
  'Puma Ruby app server (Server: Puma, X-Powered-By artifacts)',
  'Unicorn Ruby app server (Server: Unicorn)',
  'Phusion Passenger (Server: Passenger, X-Powered-By: Phusion Passenger)',
  'Thin Ruby server (Server: thin)',
  'WEBrick Ruby server (Server: WEBrick/x.y)',
  'Microsoft Kestrel — ASP.NET Core server (Server: Kestrel, developer exception page)',
  'IIS Express (Server: Microsoft-IIS/10.0 Express)',

  // ── Serving infrastructure: proxies / caches / gateways ──
  'Varnish HTTP cache (X-Varnish, Via, Age headers, default error pages)',
  'Squid proxy (Via, X-Cache, X-Squid-Error, /squid-internal- pages)',
  'HAProxy (stats page at /haproxy?stats, Server header on errors)',
  'Traefik proxy (/dashboard, /api/rawdata, /ping, /api/version)',
  'Envoy proxy (admin interface /server_info, /stats, /clusters, /config_dump)',
  'Kong API Gateway (admin API /status, Via: kong, /, X-Kong headers)',
]

export function pickAnchor() {
  const i = crypto.randomBytes(2).readUInt16BE(0) % STACK_POOL.length
  return STACK_POOL[i]
}
