# Scripts

## Directory Structure

| Path | Purpose |
|------|---------|
| `dev/` | Local development setup and tooling |
| `deploy.sh` | Production deployment via SSH |
| `homeserver-setup.sh` | Self-hosted server provisioning |
| `gen-homeserver-secrets.sh` | Generate secrets for self-hosted deployments |
| `ops/sentry_events.py` | Query recent Sentry events with a read-only API token |
| `ops/auth_identity_preflight.py` | Pre-release browser-auth identity drift and duplicate-email lockout report |
| `qa/auth/run-auth-qa.sh` | Interactive browser-auth QA with explicit pass/fail input and artifact capture |
| `stripe_setup.py` | Stripe product/price configuration |
| `check_sql_type_mismatches.py` | Pre-commit guard against SQL type drift |
| `post-deploy-smoke.sh` | Post-deploy security smoke test (auth redirect, headers, HSTS, health) |

## Local Development

```bash
bash scripts/dev/setup.sh          # First-time setup (postgres, .env, migrations, test account)
bash scripts/dev/setup.sh --reset  # Drop and recreate everything
```

## Deployment

```bash
bash scripts/deploy.sh             # Deploy current main to production
```

## Self-Hosted Bootstrap

```bash
bash scripts/gen-homeserver-secrets.sh
bash ~/Desktop/homeserver-setup.sh
```

See [Self-Hosted Setup](../docs/ops/self-hosted.md) for the complete operator
guide, including target prerequisites, human approval points, port selection,
HTTP-only validation mode, first-admin setup, client setup, backup, restore,
update, and troubleshooting.

After the stack is healthy, create the first owner account from the one-time
setup page printed by `homeserver-setup.sh`. The URL includes the generated
`CONTEXTIFY_SELF_HOSTED_SETUP_TOKEN`; `/setup` is not available without it.
The route is available only when `SELF_HOSTED=true` and returns `410 Gone`
after an owner or admin exists.

CLI fallback from the server:

```bash
cd ~/contextify-cloud
docker compose -f docker-compose.selfhosted.yml exec api \
  python -m contextify_cloud create-admin --email you@example.com
```

## Self-Hosted Backups

Create an on-demand self-hosted backup archive from the server host:

```bash
cd ~/code/projects/contextify-cloud
scripts/contextify-cloud-selfhosted backup \
  --compose-file docker-compose.selfhosted.yml \
  --output-dir ~/Library/Application\ Support/ContextifyCloud/backups
```

The archive contains a `pg_dump -Fc` database dump plus the local self-hosted
configuration files found next to the compose file. Dumps stream through
`docker compose exec -T db`, so PostgreSQL does not need a host port.
Relative backup output paths and explicit `--include-file` paths resolve from
the directory containing the compose file.

Backup archives are sensitive. They include `.env` so the server can be
restored without reconstructing credentials, which also means they contain the
database password, API signing secret, and setup token. Keep the backup
directory on encrypted local storage or another trusted encrypted volume, and
do not share archives through untrusted sync or ticketing systems.

Restore from an archive. The restore command stops the API before replacing
database contents and restarts the stack after a successful restore:

```bash
cd ~/code/projects/contextify-cloud
scripts/contextify-cloud-selfhosted restore \
  ~/Library/Application\ Support/ContextifyCloud/backups/contextify-selfhosted-YYYYMMDDTHHMMSSZ.tar \
  --compose-file docker-compose.selfhosted.yml \
  --confirm-overwrite
```

Generate a Mac Mini LaunchAgent for daily scheduled backups:

```bash
mkdir -p ~/Library/LaunchAgents
scripts/contextify-cloud-selfhosted launchd-plist \
  --repo-dir ~/code/projects/contextify-cloud \
  --compose-file docker-compose.selfhosted.yml \
  --output-dir ~/Library/Application\ Support/ContextifyCloud/backups \
  --output ~/Library/LaunchAgents/com.contextify.cloud.backup.plist
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.contextify.cloud.backup.plist
launchctl enable "gui/$(id -u)/com.contextify.cloud.backup"
```

## Self-Hosted Updates

Run an update from the server host:

```bash
cd ~/code/projects/contextify-cloud
scripts/contextify-cloud-selfhosted update \
  --repo-dir ~/code/projects/contextify-cloud \
  --compose-file docker-compose.selfhosted.yml \
  --backup-dir ~/Library/Application\ Support/ContextifyCloud/backups
```

The update command takes a pre-update backup, runs `git pull --ff-only`, rebuilds
the API image, starts the database, stops the API before migrations, runs
`alembic upgrade head`, restarts the stack with `docker compose up -d --wait`,
and verifies
`http://127.0.0.1:8443/api/v1/health`. If the health check fails, it prints the
rollback commands using the previous Git revision and points at the restore
command for the pre-update backup.

If setup selected a port other than `8443`, pass the selected loopback health
URL:

```bash
scripts/contextify-cloud-selfhosted update \
  --repo-dir ~/code/projects/contextify-cloud \
  --compose-file docker-compose.selfhosted.yml \
  --backup-dir ~/Library/Application\ Support/ContextifyCloud/backups \
  --health-url http://127.0.0.1:8444/api/v1/health
```

Update does not perform automatic rollback. It preserves a pre-update backup and
prints the exact rollback/restore commands if a step fails.

## Self-Hosted Health

Check the local self-hosted stack from the server host:

```bash
cd ~/code/projects/contextify-cloud
scripts/contextify-cloud-selfhosted health \
  --compose-file docker-compose.selfhosted.yml \
  --public-url https://<machine>.<tailnet>.ts.net
```

The command checks the compose service state, PostgreSQL readiness, loopback API
health, and the optional public Tailscale URL. It exits `0` when healthy, `1`
when reachable but degraded, and `2` when a required check fails. Add `--json`
for release proof or automation.

Generate a scheduled LaunchAgent for updates:

```bash
scripts/contextify-cloud-selfhosted launchd-plist \
  --job update \
  --repo-dir ~/code/projects/contextify-cloud \
  --compose-file docker-compose.selfhosted.yml \
  --output-dir ~/Library/Application\ Support/ContextifyCloud/backups \
  --output ~/Library/LaunchAgents/com.contextify.cloud.update.plist
```

## Post-Deploy Verification

```bash
bash scripts/post-deploy-smoke.sh                              # Test production (default)
bash scripts/post-deploy-smoke.sh https://staging.example.com  # Test a different host
```

The smoke test verifies auth redirect (303), security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), HSTS, and health endpoint status. CI runs this automatically after every deploy.

## Auth QA

```bash
bash scripts/qa/auth/run-auth-qa.sh --dry-run
BASE_URL=http://127.0.0.1:8000 bash scripts/qa/auth/run-auth-qa.sh
```

The auth QA script writes results and artifacts under `/tmp/` and requires
explicit pass/fail/skip input for high-risk manual auth checks.

## Sentry Event Checks

```bash
python scripts/ops/sentry_events.py recent-413 --stats-period 24h
```

The script reads `SENTRY_AUTH_TOKEN`, `SENTRY_ORG`, and `SENTRY_PROJECT` from the
environment or `~/.config/contextify/sentry.env`.

## Auth Identity Preflight

```bash
uv run python scripts/ops/auth_identity_preflight.py
```

Run this before auth rollout or identity-constraint migrations. Blocking rows
indicate user/tenant drift that must be repaired before release. Cross-tenant
duplicate account emails are reported as warnings because the launch guard
intentionally locks those accounts out until explicit tenant switching exists.
