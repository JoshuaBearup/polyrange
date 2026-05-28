# PolyRange — WSTG-ATHN-11 (4.4.11) MFA Bypass. Stateless Node.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-mfa-bypass-4.4.11/scenario.mjs ./classes/wstg-mfa-bypass-4.4.11/scenario.mjs
COPY classes/wstg-mfa-bypass-4.4.11/behaviour.mjs ./classes/wstg-mfa-bypass-4.4.11/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
