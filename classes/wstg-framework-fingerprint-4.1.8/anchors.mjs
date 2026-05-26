// Per-deploy anchor for WEB APPLICATION FRAMEWORK fingerprinting (4.1.8).
// The framework is identifiable from its headers / cookies / default error
// pages / default debug or info endpoints. We anchor each deploy to one
// framework so deploys spread across the real framework space. The LLM fills
// in the realistic version, headers, and the authentic body of each default
// endpoint — this list only anchors WHICH framework.

import crypto from 'node:crypto'

export const STACK_POOL = [
  // ── JVM ──
  'Spring Boot with Actuator exposed (/actuator, /actuator/env, /actuator/health, /actuator/mappings, /actuator/beans)',
  'Spring MVC classic (default /error page, JSESSIONID)',
  'Dropwizard (admin endpoints /healthcheck, /metrics, /threads, /tasks)',
  'Micronaut (/health, /env, /routes, /beans, /info management endpoints)',
  'Quarkus (/q/health, /q/metrics, /q/openapi, /q/dev dev-ui exposed)',
  'Grails (default Grails error pages, /dbconsole H2 console)',
  'Apache Struts (.action / .do extensions, default Struts error pages)',
  'Play Framework — Scala (default Play error page, PLAY_SESSION cookie)',
  'Ktor — Kotlin (Server: ktor, default error pages)',
  'Javalin / Spark Java (minimal Jetty-backed defaults)',
  'Vert.x (default error pages, metrics endpoint)',

  // ── Python ──
  'Django (csrftoken + sessionid cookies, /admin login, debug toolbar /__debug__, Werkzeug-style debug 500 when DEBUG=True)',
  'Flask (Werkzeug interactive debugger /console when DEBUG on, flask session cookie)',
  'FastAPI (/docs Swagger UI, /redoc, /openapi.json)',
  'Tornado (Server: TornadoServer, default error pages)',
  'Sanic (Server: sanic, default error JSON)',
  'Pyramid (default error pages, pyramid session)',
  'Bottle (Server: WSGIServer/bottle, default 404)',
  'Falcon API framework (default JSON error shape)',
  'web2py (/admin app, default admin interface, ticket error pages)',

  // ── Ruby ──
  'Ruby on Rails (X-Runtime, _<app>_session cookie, /rails/info/routes, /rails/info/properties, better_errors /__better_errors when dev)',
  'Sinatra (X-Powered-By: Sinatra, default error pages)',
  'Hanami (default Hanami error pages)',
  'Padrino (Padrino default pages)',

  // ── PHP ──
  'Laravel (laravel_session + XSRF-TOKEN cookies, /telescope, /horizon, /_ignition/health-check, Ignition debug pages)',
  'Symfony (/_profiler web profiler, /_wdt toolbar, app_dev.php, X-Debug-Token headers)',
  'CodeIgniter (ci_session cookie, default error pages)',
  'CakePHP (default CakePHP error pages, debug kit /debug-kit)',
  'Yii (default Yii debug toolbar /debug, _csrf cookie)',
  'Laminas / Zend (default error pages, ZF headers)',
  'Slim PHP (default Slim error pages)',
  'Phalcon (default Phalcon error pages)',

  // ── Node.js ──
  'Express (X-Powered-By: Express, default HTML 404/500 stack pages when not in production)',
  'Koa (X-Powered-By, default error pages)',
  'NestJS (X-Powered-By: Express, default /api routes, default exception JSON)',
  'Next.js (X-Powered-By: Next.js, /_next/data, /_next/static, /__nextjs_original-stack-frame dev endpoint)',
  'Nuxt (/_nuxt artifacts, __NUXT__ inline state)',
  'Fastify (default error JSON shape, Server header)',
  'Sails.js (sails.sid cookie, default blueprint routes)',
  'AdonisJS (adonis-session cookie, default error pages)',
  'LoopBack (/explorer API explorer, default API root JSON)',
  'Hapi (default Boom error JSON)',
  'Meteor (__meteor_runtime_config__ inline, /sockjs endpoints)',

  // ── .NET ──
  'ASP.NET (X-AspNet-Version, X-Powered-By: ASP.NET, ASP.NET_SessionId, /elmah.axd, /trace.axd)',
  'ASP.NET Core (developer exception page, .AspNetCore.* cookies, /swagger)',
  'ASP.NET MVC (__RequestVerificationToken, default route patterns)',

  // ── Go / Rust / Elixir ──
  'Gin (Go) — default debug routing log style, X-Powered-By artifacts',
  'Echo (Go) — default error pages',
  'Fiber (Go) — Server: Fiber',
  'Go net/http with pprof (/debug/pprof/, /debug/vars expvar)',
  'Phoenix — Elixir (_<app>_key signed session cookie, LiveDashboard /dashboard, default Phoenix error pages)',
  'Actix Web — Rust (Server: actix-web, default error pages)',
  'Axum — Rust (default tower error responses)',
  'Rocket — Rust (Server: Rocket, default catchers)',
]

export function pickAnchor() {
  const i = crypto.randomBytes(2).readUInt16BE(0) % STACK_POOL.length
  return STACK_POOL[i]
}
