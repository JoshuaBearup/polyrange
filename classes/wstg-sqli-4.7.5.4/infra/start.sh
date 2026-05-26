#!/bin/sh
# Process orchestration: start postgres in background, wait for it, then
# exec into the Node runtime which connects to localhost:5432.
set -e

echo "[start] starting postgres..."
docker-entrypoint.sh postgres &
PG_PID=$!

echo "[start] waiting for postgres to accept connections..."
until pg_isready -U postgres -h localhost > /dev/null 2>&1; do
  sleep 0.3
done
echo "[start] postgres ready"

exec node /app/runtime/server.mjs
