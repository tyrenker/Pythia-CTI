#!/bin/sh
# Entrypoint: initialize DB and seed if empty, then hand off to CMD.
set -e

DB_PATH="${PYTHIA_DB_FILE:-/app/db/pythia.db}"

# Create tables on every start (no-op if they exist).
python -c "from pythia.core.db import init_db; init_db()"

# Auto-seed only when the actors table is empty (fresh DB or first run).
ACTOR_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM threat_actors;" 2>/dev/null || echo "0")

if [ "$ACTOR_COUNT" = "0" ]; then
    echo "[pythia] Empty database detected — running initial seed (this takes ~60s on first run)..."
    pythia sync
    echo "[pythia] Seed complete."
fi

exec "$@"
