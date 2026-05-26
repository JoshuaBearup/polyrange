# PolyRange — WSTG-XSS-4.7.1 (Reflected XSS)
# Minimal Node container. No backing services required for reflected XSS.
# Real HTTP server reflecting unescaped input.

FROM node:20-alpine

WORKDIR /app

# Install class-specific runtime deps (just zod for XSS)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy shared runtime + class behaviour
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-xss-4.7.1/scenario.mjs ./classes/wstg-xss-4.7.1/scenario.mjs
COPY classes/wstg-xss-4.7.1/behaviour.mjs ./classes/wstg-xss-4.7.1/behaviour.mjs

# Per-deploy manifest is baked in by the deploy script
COPY manifest.json ./manifest.json

ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "runtime/server.mjs"]
