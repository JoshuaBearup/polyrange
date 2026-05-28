# PolyRange — WSTG-ATHN-03 (4.4.3) Weak Lockout. Postgres + Node sidecar.
FROM postgres:16-alpine
RUN apk add --no-cache nodejs npm
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-weak-lockout-4.4.3/scenario.mjs ./classes/wstg-weak-lockout-4.4.3/scenario.mjs
COPY classes/wstg-weak-lockout-4.4.3/behaviour.mjs ./classes/wstg-weak-lockout-4.4.3/behaviour.mjs
COPY manifest.json ./manifest.json
COPY start.sh /start.sh
RUN chmod +x /start.sh
ENV POSTGRES_PASSWORD=polyrange
ENV POSTGRES_USER=postgres
ENV POSTGRES_DB=app
ENV DATABASE_URL=postgresql://postgres:polyrange@localhost:5432/app
ENV PORT=8080
ENV NODE_ENV=production
ENV PGDATA=/var/lib/postgresql/data
EXPOSE 8080
CMD ["/start.sh"]
