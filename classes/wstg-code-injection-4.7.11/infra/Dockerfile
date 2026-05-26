# PolyRange — WSTG-INPV-11 (4.7.11) Code Injection (polyglot).
# Node front (HTTP + WAF + gates) proxies the sink to a real localhost backend
# in the per-deploy language. This image carries the language runtimes the
# backends need; the manifest's scenario.language selects which one runs.

FROM node:20-alpine

# Language runtimes for the eval backends (node is already in the base image).
RUN apk add --no-cache python3 ruby \
 && (apk add --no-cache php83 && ln -sf /usr/bin/php83 /usr/local/bin/php \
     || (apk add --no-cache php82 && ln -sf /usr/bin/php82 /usr/local/bin/php))

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-code-injection-4.7.11/scenario.mjs ./classes/wstg-code-injection-4.7.11/scenario.mjs
COPY classes/wstg-code-injection-4.7.11/behaviour.mjs ./classes/wstg-code-injection-4.7.11/behaviour.mjs
COPY classes/wstg-code-injection-4.7.11/backends/ ./classes/wstg-code-injection-4.7.11/backends/

COPY manifest.json ./manifest.json

ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "runtime/server.mjs"]
