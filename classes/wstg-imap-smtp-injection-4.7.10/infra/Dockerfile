# PolyRange — WSTG-INPV-10 (4.7.10) IMAP/SMTP Injection. Node (in-process IMAP server).
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-imap-smtp-injection-4.7.10/scenario.mjs ./classes/wstg-imap-smtp-injection-4.7.10/scenario.mjs
COPY classes/wstg-imap-smtp-injection-4.7.10/behaviour.mjs ./classes/wstg-imap-smtp-injection-4.7.10/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
