# PolyRange — WSTG-BUSL-02 (4.10.2) Ability to Forge Requests. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-forge-requests-4.10.2/scenario.mjs ./classes/wstg-forge-requests-4.10.2/scenario.mjs
COPY classes/wstg-forge-requests-4.10.2/behaviour.mjs ./classes/wstg-forge-requests-4.10.2/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
