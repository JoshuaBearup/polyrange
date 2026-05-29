# PolyRange — WSTG-INPV-05.8 (4.7.5.8) Client-Side SQL Injection. Stateless Node.
# sql.js (WebAssembly SQLite) is loaded in the visitor's browser from a public
# CDN; the container ships only the static HTML shell and seed-injection logic.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-sqli-client-4.7.5.8/scenario.mjs ./classes/wstg-sqli-client-4.7.5.8/scenario.mjs
COPY classes/wstg-sqli-client-4.7.5.8/behaviour.mjs ./classes/wstg-sqli-client-4.7.5.8/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
