# PolyRange — WSTG-INPV-10 (4.7.10) IMAP Injection — REAL dovecot IMAP server.
FROM node:20-alpine
RUN apk add --no-cache dovecot && adduser -D -H -u 5000 vmail
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-imap-smtp-injection-4.7.10/scenario.mjs ./classes/wstg-imap-smtp-injection-4.7.10/scenario.mjs
COPY classes/wstg-imap-smtp-injection-4.7.10/behaviour.mjs ./classes/wstg-imap-smtp-injection-4.7.10/behaviour.mjs
COPY manifest.json ./manifest.json
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY seed-maildir.mjs /app/seed-maildir.mjs
COPY start-dovecot.sh /start.sh
RUN chmod +x /start.sh
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["/start.sh"]
