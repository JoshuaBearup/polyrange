# PolyRange — WSTG-CONF-04 (wstg-backup-files-4.2.4) Backup and Unreferenced Files
# Minimal stateless Node container. The runtime sets fingerprint headers on
# every response and serves the stack-default diagnostic endpoints.

FROM node:20-alpine

WORKDIR /app

# Install class-specific runtime deps (just zod)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy shared runtime + class behaviour
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-backup-files-4.2.4/scenario.mjs ./classes/wstg-backup-files-4.2.4/scenario.mjs
COPY classes/wstg-backup-files-4.2.4/behaviour.mjs ./classes/wstg-backup-files-4.2.4/behaviour.mjs

# Per-deploy manifest is baked in by the deploy script
COPY manifest.json ./manifest.json

ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "runtime/server.mjs"]
