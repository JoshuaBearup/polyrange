# PolyRange — WSTG-INPV-14 (4.7.14) Incubated Vulnerability. Stateless Node + in-memory store.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-incubated-4.7.14/scenario.mjs ./classes/wstg-incubated-4.7.14/scenario.mjs
COPY classes/wstg-incubated-4.7.14/behaviour.mjs ./classes/wstg-incubated-4.7.14/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
