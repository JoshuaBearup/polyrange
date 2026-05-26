# PolyRange — WSTG-INPV-19 (4.7.19) SSRF.
# Node front (HTTP + WAF + gates + the server-side fetch sink) plus a
# loopback-bound internal service (the pivot target) started by the runtime.
# All Node — no extra runtimes needed.

FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-ssrf-4.7.19/scenario.mjs ./classes/wstg-ssrf-4.7.19/scenario.mjs
COPY classes/wstg-ssrf-4.7.19/behaviour.mjs ./classes/wstg-ssrf-4.7.19/behaviour.mjs
COPY classes/wstg-ssrf-4.7.19/backends/ ./classes/wstg-ssrf-4.7.19/backends/

COPY manifest.json ./manifest.json

ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "runtime/server.mjs"]
