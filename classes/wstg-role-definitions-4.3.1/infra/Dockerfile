# PolyRange — WSTG-IDNT-01 (4.3.1) Test Role Definitions.
# Real Postgres + Node in the same container (mirrors IDOR).

FROM postgres:16-alpine

RUN apk add --no-cache nodejs npm

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-role-definitions-4.3.1/scenario.mjs ./classes/wstg-role-definitions-4.3.1/scenario.mjs
COPY classes/wstg-role-definitions-4.3.1/behaviour.mjs ./classes/wstg-role-definitions-4.3.1/behaviour.mjs

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
