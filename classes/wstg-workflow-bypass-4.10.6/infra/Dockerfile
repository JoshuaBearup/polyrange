# PolyRange — WSTG-BUSL-06 (4.10.6) Workflow Circumvention. Node (in-memory).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-workflow-bypass-4.10.6/scenario.mjs ./classes/wstg-workflow-bypass-4.10.6/scenario.mjs
COPY classes/wstg-workflow-bypass-4.10.6/behaviour.mjs ./classes/wstg-workflow-bypass-4.10.6/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
