#!/bin/sh
# Start postgres in the background, wait for it, then exec the Node runtime
# (connects to localhost:5432 via DATABASE_URL).
set -e
echo "[start] starting postgres..."
docker-entrypoint.sh postgres &
echo "[start] waiting for postgres..."
until pg_isready -U postgres -h localhost > /dev/null 2>&1; do sleep 0.3; done
echo "[start] postgres ready"
exec node /app/runtime/server.mjs
