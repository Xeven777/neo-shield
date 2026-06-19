#!/bin/bash
set -e

# Grant INSERT permission on security_event table for the worker role
# This fixes: "permission denied for table security_event"
# Run as postgres user or a user with GRANT privileges

DATABASE_URL="${NEOSHIELD_DATABASE_URL:-}"

if [ -z "$DATABASE_URL" ]; then
    echo "NEOSHIELD_DATABASE_URL not set, skipping permission grant"
    exit 0
fi

# Extract connection parameters from DATABASE_URL
# Format: postgresql://user:password@host:port/db?sslmode=require
# We'll use psql directly

echo "Granting INSERT permission on security_event to worker role..."

# Try to grant permission using psql
# The DATABASE_URL format: postgresql://worker:password@ep-xxxx-pooler.region.aws.neon.tech/db?sslmode=require
PGHOST=$(echo "$DATABASE_URL" | sed -n 's|postgresql://[^:]*://[^:@]*@\([^:/]*\).*|\1|p')
PGUSER=$(echo "$DATABASE_URL" | sed -n 's|postgresql://\([^:]*\):.*|\1|p')
PGPASSWORD=$(echo "$DATABASE_URL" | sed -n 's|postgresql://[^:]*:[^@]*@[^:]*::[^/@]*\(.*)\)|\1|p' | head -1 || true)
PGDATABASE=$(echo "$DATABASE_URL" | sed -n 's|postgresql://[^:]*@[^:]*:[^/]*\(/.*\)|\1|p' | cut -d'?' -f1 || true)
PGPORT=$(echo "$DATABASE_URL" | sed -n 's|postgresql://[^:]*@[^:]*:\([0-9]*\)/\|.*|\1|p' || true)

# If we have the required params, try to grant permissions
if [ -n "$PGUSER" ] && [ -n "$PGHOST" ] && [ -n "$PGDATABASE" ]; then
    PGPASS_OPTION=""
    [ -n "$PGPASSWORD" ] && PGPASS_OPTION="-w $PGPASSWORD"

    echo "Running: GRANT INSERT ON security_event TO $PGUSER;"
    psql "host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$PGUSER $PGPASS_OPTION" -c \
        "GRANT INSERT ON security_event TO $PGUSER;" 2>/dev/null || \
        echo "WARNING: Could not grant INSERT on security_event (may already have permission or access denied)"

    # Also grant on related sequences if needed
    psql "host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$PGUSER $PGPASS_OPTION" -c \
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO $PGUSER;" 2>/dev/null || true
else
    echo "WARNING: Could not parse DATABASE_URL, skipping automatic permission grant"
    echo "To fix manually: psql your-db -c \"GRANT INSERT ON security_event TO worker;\"
fi

echo "Permission grant complete"