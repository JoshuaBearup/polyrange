# PolyRange — WSTG-ATHN-04 (4.4.4) SQL auth bypass — SQLite dialect (in-process
# via sql.js, no DB server). Postgres/MySQL dialects use a multi-engine image.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-sql-auth-bypass-4.4.4/scenario.mjs ./classes/wstg-sql-auth-bypass-4.4.4/scenario.mjs
COPY classes/wstg-sql-auth-bypass-4.4.4/behaviour.mjs ./classes/wstg-sql-auth-bypass-4.4.4/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
