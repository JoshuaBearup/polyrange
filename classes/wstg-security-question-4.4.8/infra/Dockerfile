# PolyRange — WSTG-ATHN-08 (4.4.8) Weak Security Question Answer. Stateless Node (in-memory).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-security-question-4.4.8/scenario.mjs ./classes/wstg-security-question-4.4.8/scenario.mjs
COPY classes/wstg-security-question-4.4.8/behaviour.mjs ./classes/wstg-security-question-4.4.8/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
