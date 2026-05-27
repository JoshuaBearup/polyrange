# PolyRange — WSTG-CRYP-02 (4.9.2) Padding Oracle. Node (in-memory, no DB).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-padding-oracle-4.9.2/scenario.mjs ./classes/wstg-padding-oracle-4.9.2/scenario.mjs
COPY classes/wstg-padding-oracle-4.9.2/behaviour.mjs ./classes/wstg-padding-oracle-4.9.2/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
