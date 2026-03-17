#!/usr/bin/env bash
# Waits for PostgreSQL to be ready, then runs initial data bootstrap.
set -e

echo "Waiting for PostgreSQL at ${POSTGRES_SERVER}:${POSTGRES_PORT:-5432}..."
until python -c "
import psycopg2, os, sys
try:
    psycopg2.connect(
        host=os.environ['POSTGRES_SERVER'],
        port=int(os.environ.get('POSTGRES_PORT', 5432)),
        dbname=os.environ['POSTGRES_DB'],
        user=os.environ['POSTGRES_USER'],
        password=os.environ['POSTGRES_PASSWORD'],
        connect_timeout=3,
    )
    sys.exit(0)
except Exception:
    sys.exit(1)
"; do
  echo "  ...waiting"
  sleep 2
done

echo "PostgreSQL is ready."
echo "Running initial data bootstrap..."
python /app/app/initial_data.py

echo "Starting application..."
exec "$@"
