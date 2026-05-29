# PolyRange — WSTG-CLNT-10 (4.11.10) SSE Origin Check. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-sse-4.11.10/scenario.mjs ./classes/wstg-sse-4.11.10/scenario.mjs
COPY classes/wstg-sse-4.11.10/behaviour.mjs ./classes/wstg-sse-4.11.10/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
