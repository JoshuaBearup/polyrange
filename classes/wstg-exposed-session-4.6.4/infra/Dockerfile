# PolyRange — WSTG-SESS-04 (4.6.4) Exposed Session Variables. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-exposed-session-4.6.4/scenario.mjs ./classes/wstg-exposed-session-4.6.4/scenario.mjs
COPY classes/wstg-exposed-session-4.6.4/behaviour.mjs ./classes/wstg-exposed-session-4.6.4/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
