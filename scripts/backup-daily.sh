#!/usr/bin/env bash
# Daily pg_dump backup with retention.
#
# Runs under the deploy user's crontab. deploy is in the docker group, so the
# docker compose invocation does not need sudo.
#
# Produces a compressed (-Fc) dump at:
#   /opt/contextify-cloud/backups/daily/contextify-YYYYMMDDTHHMMSSZ.dump
#
# Retention: deletes dumps older than RETENTION_DAYS, but never takes the total
# count below MIN_KEEP. This guards against a gap in cron (e.g. server outage
# longer than RETENTION_DAYS) wiping the only remaining dumps.
#
# Alerting: failures log to the systemd journal under tag "contextify-backup"
# at priority user.err. Inspect with:
#   journalctl -t contextify-backup -p err -n 50
# Silence is not monitored; ct-942 tracks off-server copies and a dead-man
# alert.
#
# See docs/ops/backup-security.md for design rationale.

set -euo pipefail
export PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}

# Dumps contain the full production database and must not leak beyond the
# deploy user. Set umask before any mkdir / file creation so new dirs land
# as 700 and new files as 600 regardless of the inherited umask.
umask 077

# Production defaults. Override via env for local dry-runs (see tests/ops/).
BACKUP_DIR=${BACKUP_DIR:-/opt/contextify-cloud/backups/daily}
COMPOSE_FILE=${COMPOSE_FILE:-/opt/contextify-cloud/docker-compose.prod.yml}
DB_SERVICE=${DB_SERVICE:-db}
DB_USER=${DB_USER:-contextify}
DB_NAME=${DB_NAME:-contextify}
RETENTION_DAYS=${RETENTION_DAYS:-30}
MIN_KEEP=${MIN_KEEP:-7}
MIN_DUMP_BYTES=${MIN_DUMP_BYTES:-$((1024 * 1024))}
LOG_TAG=${LOG_TAG:-contextify-backup}

log() {
  logger -t "$LOG_TAG" -p user.info -- "$*"
  printf '[%s] %s\n' "$LOG_TAG" "$*"
}

err() {
  logger -t "$LOG_TAG" -p user.err -- "$*"
  printf '[%s] ERROR: %s\n' "$LOG_TAG" "$*" >&2
}

fail() {
  err "$*"
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker not on PATH"
[[ -f "$COMPOSE_FILE" ]] || fail "compose file not found: $COMPOSE_FILE"

mkdir -p "$BACKUP_DIR"
# Defensive: tighten perms even if the dir pre-existed with a broader mode
# (e.g. created manually under a 022 umask before this script ran).
chmod 700 "$BACKUP_DIR"

# Preflight: confirm the db container is up and accepting connections before
# we attempt a dump. Gives a clearer journal message than a raw pg_dump error
# and avoids creating a .partial file when the db is plainly unreachable.
# PG_ISREADY_SKIP=1 lets the unit tests bypass this against the docker shim.
if [[ "${PG_ISREADY_SKIP:-0}" != "1" ]]; then
  if ! docker compose -f "$COMPOSE_FILE" exec -T "$DB_SERVICE" \
        pg_isready -U "$DB_USER" -q >/dev/null 2>&1; then
    fail "pg_isready preflight failed: db not accepting connections"
  fi
fi

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="$BACKUP_DIR/contextify-${ts}.dump"
tmp="${out}.partial"

log "starting pg_dump -> $out"
# Capture the real pg_dump exit code. The `if ! cmd` pattern would run the
# failure branch with `$?` == 0 because `!` inverts the exit; `|| rc=$?`
# preserves the original code under `set -e`.
rc=0
docker compose -f "$COMPOSE_FILE" exec -T "$DB_SERVICE" \
    pg_dump -U "$DB_USER" -Fc "$DB_NAME" > "$tmp" || rc=$?
if (( rc != 0 )); then
  rm -f "$tmp"
  fail "pg_dump failed (exit $rc)"
fi

size=$(wc -c < "$tmp" | tr -d ' ')
if (( size < MIN_DUMP_BYTES )); then
  rm -f "$tmp"
  fail "dump too small ($size bytes < $MIN_DUMP_BYTES); refusing to rotate"
fi

mv "$tmp" "$out"
log "dump ok: $out ($size bytes)"

# Retention only runs after a confirmed good dump landed above, so rotation
# can never empty the backup set in response to an upstream failure.
# Portable across GNU (Linux) and BSD (macOS) coreutils: uses stat -c / -f
# instead of `find -printf`, and `while read` instead of `mapfile`.
list_dumps_by_age() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'contextify-*.dump' -print0 \
    | while IFS= read -r -d '' path; do
        mtime=$(stat -c %Y "$path" 2>/dev/null || stat -f %m "$path")
        printf '%s\t%s\n' "$mtime" "$path"
      done \
    | sort -n
}

total=$(list_dumps_by_age | wc -l | tr -d ' ')
if (( total > MIN_KEEP )); then
  max_delete=$(( total - MIN_KEEP ))
  deleted=0
  now_s=$(date +%s)
  while IFS=$'\t' read -r mtime path; do
    (( deleted >= max_delete )) && break
    age_s=$(( now_s - mtime ))
    if (( age_s > RETENTION_DAYS * 86400 )); then
      log "deleting expired: $path"
      rm -f "$path"
      deleted=$(( deleted + 1 ))
    else
      break
    fi
  done < <(list_dumps_by_age)
fi

retained=$(
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'contextify-*.dump' | wc -l | tr -d ' '
)
log "complete: $retained dump(s) retained"
