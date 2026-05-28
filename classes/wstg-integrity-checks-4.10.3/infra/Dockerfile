# PolyRange — WSTG-BUSL-03 (4.10.3) Integrity Checks. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-integrity-checks-4.10.3/scenario.mjs ./classes/wstg-integrity-checks-4.10.3/scenario.mjs
COPY classes/wstg-integrity-checks-4.10.3/behaviour.mjs ./classes/wstg-integrity-checks-4.10.3/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
