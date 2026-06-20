# Contextify Cloud

Cloud sync and team features backend for [Contextify](https://contextify.sh).

## Security Defaults

- Public API docs are disabled by default. Set `ENABLE_DOCS=true` only for local development.
- Public self-serve registration is disabled by default. Set `ENABLE_REGISTRATION=true` only if you intentionally want open signup.
- Production deployments should keep PostgreSQL internal to Docker networking; do not publish port `5432` on the host.
- `/api/v1/health` is intentionally minimal and returns only service status.
- The dashboard enforces a strict Content-Security-Policy: `default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'`. Bootstrap, Bootstrap Icons (including fonts), and HTMX are vendored as local static files under `contextify_cloud/static/vendor/`; no CDN origins are required or allowed.
- Sentry-compatible monitoring is supported via `SENTRY_DSN` plus `ERROR_MONITORING_ENABLED=true`. CI deploys and `scripts/deploy.sh` forward the deployed git SHA into `SENTRY_RELEASE` so production events carry a release identifier.

## Toolchain

- **Python:** 3.13+ (required, see `requires-python` in pyproject.toml)
- **Package manager:** [uv](https://docs.astral.sh/uv/) 0.11+
- **Database:** PostgreSQL 18
- **Linting:** ruff (blocking in CI and pre-commit)
- **Type checking:** mypy strict (blocking in CI and pre-commit)

## Quick Start

**Automated** (creates postgres, .env, migrations, test account):

```bash
bash scripts/dev/setup.sh
uv run uvicorn contextify_cloud.main:app --reload --port 8443
```

Reset everything: `bash scripts/dev/setup.sh --reset`

**Manual:**

```bash
# Start PostgreSQL (local brew or Docker)
brew services start postgresql@18   # OR: docker compose up -d db

uv sync --extra dev                 # Install dependencies
git config core.hooksPath .githooks # Enable pre-commit hooks
cp .env.example .env                # Create .env, then edit it
uv run alembic upgrade head         # Run migrations
uv run uvicorn contextify_cloud.main:app --reload --port 8443
```

Alembic uses the runtime `DATABASE_URL`, not the fallback value in `alembic.ini`.

## Runtime Profiles and Source Mirror

The private `contextify-cloud` repository is the canonical source. The public
Personal Self-Hosted distribution is a generated source-available mirror, not a
manual fork. Maintainers generate that mirror from
`config/self-hosted-export-manifest.json` with:

```bash
python scripts/export_self_hosted.py --output /tmp/contextify-cloud-selfhosted
```

The export manifest is the only source of truth for copied files. The exporter
builds a deterministic mirror, writes `.contextify-export.json`, projects a
Personal Self-Hosted `pyproject.toml`, and writes `requirements.lock` from
`uv export --locked --no-dev --no-emit-project`. The Personal mirror excludes
hosted-only Stripe dependencies, billing routes, internal support/growth
routes, hosted ops routes, and Stripe setup scripts.

Runtime profiles:

| Profile | Selection | Intended surface |
|---------|-----------|------------------|
| Personal Self-Hosted | `SELF_HOSTED=true` | Solo/personal server with sync, search, device auth, account APIs, health, setup, backup, and restore |

Personal Self-Hosted excludes hosted-only Stripe billing, internal support,
growth, hosted ops, team, invitation, analytics, tenant-admin, and commercial
license-gated route groups.

Personal Self-Hosted is distributed under the Functional Source License,
Version 1.1, Apache 2.0 Future License (`FSL-1.1-Apache-2.0`). Each
released version automatically becomes available under the Apache License,
Version 2.0 on the second anniversary of that version's release date.

The generated mirror remains source-available/proprietary unless a release
artifact states different license terms. Do not patch the generated mirror by
hand; change the canonical repo and regenerate it.

## Full Stack (Docker)

Local dev runs uvicorn directly on the host for hot reload and debugger access. To test in a production-like container (same Dockerfile, entrypoint, and migrations as deployed):

```bash
docker compose up -d
```

This runs both the API container and Postgres. The entrypoint runs `alembic upgrade head` then starts uvicorn, matching the production deploy path. Use this before deploying if you need to verify container-specific behavior (e.g. entrypoint sequencing, dependency resolution, volume mounts).

API listens on `127.0.0.1:8443` by default. If you enable docs locally, they are available at `http://127.0.0.1:8443/api/docs`.

In a generated Personal Self-Hosted mirror, start the stack with:

```bash
docker compose -f docker-compose.selfhosted.yml up -d
```

The mirror Dockerfile installs from `requirements.lock` and then installs the
project without hosted extras. The homeserver setup script generates the mirror
outside the private checkout and sets `CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT` so
Compose builds the Personal image from that mirror rather than the canonical
hosted source tree.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/health | Health check |
| POST | /api/v1/auth/register | Legacy/programmatic tenant bootstrap that returns a machine API key when `ENABLE_REGISTRATION=true` |
| POST | /api/v1/auth/login | Legacy/programmatic API-key login; not used for browser dashboard sessions |
| GET/POST | /cloud/register | Browser signup with email and password |
| GET/POST | /cloud/login | Browser login with email and password |
| GET/POST | /cloud/forgot-password | Request password reset email |
| GET/POST | /cloud/device | Browser device-code authorization for local clients |
| POST | /api/v1/auth/api-keys | Generate API key |
| POST | /api/v1/sync/push | Push entries from local app |
| GET | /api/v1/sync/status | Sync health check |
| GET | /api/v1/search | Full-text search |

Human browser login uses email/password at `/cloud/login` and server-side
`user_sessions` behind the `ctx_session` cookie. API keys are machine
credentials managed from Cloud Settings and device handoff; they are not
browser passwords and are not accepted for dashboard login. Transactional auth
email uses Resend in production and fake log delivery when `RESEND_API_KEY` is
empty. See `docs/user/auth-workflows.md`, `docs/engineering/security-architecture.md`,
`docs/ops/transactional-email.md`, and `docs/ops/browser-auth-migration.md`.

## Testing and Linting

```bash
uv run pytest --tb=short -q -m "not e2e and not slow"  # CI unit/integration lane
uv run pytest --cov=contextify_cloud -m "not e2e and not slow"  # Coverage for CI lane
uvx ruff check .                                        # Lint (blocking)
uv run mypy contextify_cloud/                           # Type check, strict (blocking)
uv run python scripts/check_sql_type_mismatches.py  # SQL type guard
```

CI excludes E2E and slow real-Postgres tests from the unit test job with
`-m "not e2e and not slow"`. E2E tests run in a dedicated `e2e` job, while
slow tests are intentionally outside the default blocking lane. A plain
`uv run pytest` without `-m` collects every lane locally, including tests that
require Postgres, Playwright browsers, or large fixtures.

### E2E Tests (Playwright)

E2E tests live in `tests/e2e/` and use Playwright to drive a real browser against a running server. 19 tests cover CSP enforcement, login, dashboard rendering, and registration.

**Prerequisites:** running Postgres with an `e2e` database, and Playwright browsers installed.

```bash
# Install Playwright browsers (first time only)
uv run playwright install chromium

# Run E2E tests (starts its own uvicorn server automatically)
uv run pytest tests/e2e/ -v

# Point tests at an already-running server instead of starting one
E2E_BASE_URL=http://127.0.0.1:8443 uv run pytest tests/e2e/ -v
```

The `E2E_BASE_URL` env var skips server startup and connects to an existing instance. This is how the CI `e2e` job works: it starts uvicorn as a separate step, then sets `E2E_BASE_URL` before invoking pytest.

## Pre-commit Hook

The `.githooks/pre-commit` hook runs ruff, mypy, and the SQL type guard before each commit. Enable with:

```bash
git config core.hooksPath .githooks
```

## CI/CD

CI runs on every push to main via GitHub Actions (`.github/workflows/ci.yml`):

- **lint-and-test:** ruff (blocking), mypy strict (blocking), SQL type guard, pytest (excludes E2E and slow tests via `-m "not e2e and not slow"`)
- **migration-smoke:** alembic upgrade head + alembic check against real Postgres 18
- **e2e:** Playwright browser tests against a live uvicorn instance with a Postgres 18 service; traces uploaded on failure
- **deploy:** auto-deploys to production on green main via SSH, with health check and smoke test; requires lint-and-test, migration-smoke, AND e2e to pass

All checks are blocking. CI failures prevent deploy.

## Related Repos

This repo is the **cloud API** (`cloud.contextify.sh`). The product has two other components in the main contextify repo:

| Component | Repo | Local Dev | Port |
|-----------|------|-----------|------|
| **Cloud API** | contextify-cloud (this repo) | `uv run uvicorn contextify_cloud.main:app --reload --port 8443` | 8443 |
| **Marketing website** | contextify (`website/`) | `cd website && python3 -m http.server 8000` | 8000 |
| **macOS/Linux app** | contextify | Xcode or `bash scripts/xc.sh build` | n/a |

The marketing website links to cloud pages (pricing, sign up). The cloud dashboard links back to contextify.sh. When testing flows that cross boundaries (e.g. pricing page to checkout), run both local servers.

Worktrees are paired: if you're in `contextify-cloud-wb1`, use `contextify-wb1` for website changes (never cross worktree numbers).

## Production Monitoring

See `docs/ops/error-monitoring.md` for the monitoring setup, smoke-test flow, alert rules, and rollback steps.

## Incident Response

See `docs/ops/live-hotfix-playbook.md` for the production hotfix workflow,
rollback material requirements, and Bloon checkpoint template used during the
March 2026 incident window.
