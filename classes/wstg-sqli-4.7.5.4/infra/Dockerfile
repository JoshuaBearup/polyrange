# PolyRange — WSTG-INPV-05.4 (PostgreSQL SQL Injection)
# Real PostgreSQL + Node app in the same container.
# The Node app issues string-concatenated queries against real Postgres
# (no parameterisation) — vulnerable to UNION-based injection.

FROM postgres:16-alpine

RUN apk add --no-cache nodejs npm

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-sqli-4.7.5.4/scenario.mjs ./classes/wstg-sqli-4.7.5.4/scenario.mjs
COPY classes/wstg-sqli-4.7.5.4/behaviour.mjs ./classes/wstg-sqli-4.7.5.4/behaviour.mjs

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
