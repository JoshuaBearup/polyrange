# PolyRange — WSTG-BUSL-04 (4.10.4) Process Timing. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-process-timing-4.10.4/scenario.mjs ./classes/wstg-process-timing-4.10.4/scenario.mjs
COPY classes/wstg-process-timing-4.10.4/behaviour.mjs ./classes/wstg-process-timing-4.10.4/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
