# PolyRange — WSTG-BUSL-01 (4.10.1) Business Logic price tampering. Node (in-memory).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-business-logic-price-4.10.1/scenario.mjs ./classes/wstg-business-logic-price-4.10.1/scenario.mjs
COPY classes/wstg-business-logic-price-4.10.1/behaviour.mjs ./classes/wstg-business-logic-price-4.10.1/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
