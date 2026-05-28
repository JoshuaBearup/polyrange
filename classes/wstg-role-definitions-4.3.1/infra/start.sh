#!/bin/sh
# Process orchestration: start postgres, wait for it, exec node runtime.
set -e

echo "[start] starting postgres..."
docker-entrypoint.sh postgres &

echo "[start] waiting for postgres to accept connections..."
until pg_isready -U postgres -h localhost > /dev/null 2>&1; do
  sleep 0.3
done
echo "[start] postgres ready"

exec node /app/runtime/server.mjs
