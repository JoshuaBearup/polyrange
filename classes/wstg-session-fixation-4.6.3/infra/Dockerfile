# PolyRange — WSTG-SESS-03 (4.6.3) Session Fixation. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-session-fixation-4.6.3/scenario.mjs ./classes/wstg-session-fixation-4.6.3/scenario.mjs
COPY classes/wstg-session-fixation-4.6.3/behaviour.mjs ./classes/wstg-session-fixation-4.6.3/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
