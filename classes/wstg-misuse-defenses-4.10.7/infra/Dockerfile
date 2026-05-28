# PolyRange — WSTG-BUSL-07 (4.10.7) Defenses Against Application Misuse. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-misuse-defenses-4.10.7/scenario.mjs ./classes/wstg-misuse-defenses-4.10.7/scenario.mjs
COPY classes/wstg-misuse-defenses-4.10.7/behaviour.mjs ./classes/wstg-misuse-defenses-4.10.7/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
