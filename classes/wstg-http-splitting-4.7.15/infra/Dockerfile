# PolyRange — WSTG-INPV-15 (4.7.15) HTTP Splitting / Smuggling. Default
# image (splitting half) — single-process Node. The smuggling half uses
# Dockerfile.smuggling, selected per deploy by manifest.infraVariant.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-http-splitting-4.7.15/scenario.mjs ./classes/wstg-http-splitting-4.7.15/scenario.mjs
COPY classes/wstg-http-splitting-4.7.15/behaviour.mjs ./classes/wstg-http-splitting-4.7.15/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
