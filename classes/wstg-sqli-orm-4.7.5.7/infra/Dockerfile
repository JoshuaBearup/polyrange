# PolyRange — WSTG-INPV-05.7 (4.7.5.7) SQL Injection via ORM.
# Real Postgres + Node + Sequelize in the same container. The Node app issues
# searches through Sequelize.findAll with a sequelize.literal() WHERE fragment
# that concatenates user input — the canonical ORM escape-hatch SQLi sink.

FROM postgres:16-alpine

# Add Node.js to the postgres image
RUN apk add --no-cache nodejs npm

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-sqli-orm-4.7.5.7/scenario.mjs ./classes/wstg-sqli-orm-4.7.5.7/scenario.mjs
COPY classes/wstg-sqli-orm-4.7.5.7/behaviour.mjs ./classes/wstg-sqli-orm-4.7.5.7/behaviour.mjs

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
