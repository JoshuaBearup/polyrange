# PolyRange — WSTG-INPV-17 (4.7.17) Host Header Injection. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-host-header-4.7.17/scenario.mjs ./classes/wstg-host-header-4.7.17/scenario.mjs
COPY classes/wstg-host-header-4.7.17/behaviour.mjs ./classes/wstg-host-header-4.7.17/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
