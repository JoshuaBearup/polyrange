# PolyRange — WSTG-INPV-18 (4.7.18) SSTI. Node front + a real Python/Jinja2 render backend (localhost).
FROM node:20-alpine
RUN apk add --no-cache python3 py3-jinja2
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-ssti-4.7.18/scenario.mjs ./classes/wstg-ssti-4.7.18/scenario.mjs
COPY classes/wstg-ssti-4.7.18/behaviour.mjs ./classes/wstg-ssti-4.7.18/behaviour.mjs
COPY classes/wstg-ssti-4.7.18/backends/ ./classes/wstg-ssti-4.7.18/backends/
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
