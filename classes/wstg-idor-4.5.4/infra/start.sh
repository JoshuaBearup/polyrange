#!/bin/sh
# Process orchestration: start postgres in background, wait for it, then
# exec into the Node runtime which connects to localhost:5432 and applies
# the per-deploy schema + seed data from the manifest.
set -e

echo "[start] starting postgres..."
# Use the postgres image's own entrypoint to handle init, password, db creation
docker-entrypoint.sh postgres &
PG_PID=$!

echo "[start] waiting for postgres to accept connections..."
until pg_isready -U postgres -h localhost > /dev/null 2>&1; do
  sleep 0.3
done
echo "[start] postgres ready"

# Exec into the Node runtime (process orchestration: when node exits, the
# container exits — postgres will be killed by container teardown)
exec node /app/runtime/server.mjs
