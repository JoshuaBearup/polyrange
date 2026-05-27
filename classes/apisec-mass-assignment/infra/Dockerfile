# PolyRange — WSTG-Mass Assignment-4.5.4 (Mass Assignment)
# Real PostgreSQL + Node app in the same container.
# The Node app issues lookups without authorisation checks against real Postgres.

FROM postgres:16-alpine

# Add Node.js to the postgres image
RUN apk add --no-cache nodejs npm

WORKDIR /app

# Install class-specific runtime deps (zod for schema, pg for Postgres client)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy shared runtime + class behaviour
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/apisec-mass-assignment/scenario.mjs ./classes/apisec-mass-assignment/scenario.mjs
COPY classes/apisec-mass-assignment/behaviour.mjs ./classes/apisec-mass-assignment/behaviour.mjs

# Per-deploy manifest is baked in by the deploy script
COPY manifest.json ./manifest.json

# Process-orchestration entrypoint: start postgres, wait for ready, exec node
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
