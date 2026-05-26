# PolyRange — WSTG-ATHZ-02 (4.5.2) Authorization Bypass. Stateless Node (session via cookie).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-authz-bypass-4.5.2/scenario.mjs ./classes/wstg-authz-bypass-4.5.2/scenario.mjs
COPY classes/wstg-authz-bypass-4.5.2/behaviour.mjs ./classes/wstg-authz-bypass-4.5.2/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
