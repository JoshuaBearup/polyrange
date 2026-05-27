# PolyRange — WSTG-ATHN-09 (4.4.9) Weak Password Reset. Stateless Node (in-memory).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-weak-reset-4.4.9/scenario.mjs ./classes/wstg-weak-reset-4.4.9/scenario.mjs
COPY classes/wstg-weak-reset-4.4.9/behaviour.mjs ./classes/wstg-weak-reset-4.4.9/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
