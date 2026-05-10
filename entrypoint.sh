#!/bin/sh
set -e

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

echo "Running database migrations..."
/app/.venv/bin/alembic upgrade head

echo "Starting Contextify Cloud server..."
exec /app/.venv/bin/uvicorn contextify_cloud.main:app --host 0.0.0.0 --port 8443 --no-access-log
