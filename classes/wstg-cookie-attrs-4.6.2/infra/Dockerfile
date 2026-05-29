# PolyRange — WSTG-SESS-02 (4.6.2) Testing for Cookies Attributes.
# Stateless Node. Reflection sink + signup-stamped canary cookies.

FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-cookie-attrs-4.6.2/scenario.mjs ./classes/wstg-cookie-attrs-4.6.2/scenario.mjs
COPY classes/wstg-cookie-attrs-4.6.2/behaviour.mjs ./classes/wstg-cookie-attrs-4.6.2/behaviour.mjs

COPY manifest.json ./manifest.json

ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "runtime/server.mjs"]
