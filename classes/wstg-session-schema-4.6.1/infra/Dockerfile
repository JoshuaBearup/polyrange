# PolyRange — WSTG-ERRH-01 (4.8.1) Session Schema. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-session-schema-4.6.1/scenario.mjs ./classes/wstg-session-schema-4.6.1/scenario.mjs
COPY classes/wstg-session-schema-4.6.1/behaviour.mjs ./classes/wstg-session-schema-4.6.1/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
