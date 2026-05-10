# server/

Files in this directory are deployed verbatim to the production server at
`/opt/contextify-cloud/` and are used by operators (`ops` user) and CI
(`deploy` user) on the live host. Edit them in this repo, commit, push, and
let the existing rsync-based deploy (`scripts/deploy.sh`) carry them to the
server.

Do not confuse this with `scripts/deploy.sh` at the repo root, which runs on
a developer's laptop and rsyncs the repo to the server. That script is the
courier; the file you are looking for here (`server/deploy.sh`) is the
on-server entry point.

## Contents

| Path in repo | Path on server |
|--------------|----------------|
| `server/deploy.sh` | `/opt/contextify-cloud/deploy.sh` |

## How it gets to the server

`scripts/deploy.sh` rsyncs the entire repo (excluding `.git`, `.venv`,
caches, `tests/`, etc.) into `/opt/contextify-cloud/`. The `server/`
directory is included by default, so after a normal deploy the script
exists at `/opt/contextify-cloud/server/deploy.sh`.

Operators expect to find the wrapper at `/opt/contextify-cloud/deploy.sh`
(no `server/` prefix), so the first-time install creates a symlink:

```bash
ssh deploy@174.138.94.110 \
  'ln -sfn /opt/contextify-cloud/server/deploy.sh /opt/contextify-cloud/deploy.sh'
```

Subsequent deploys keep the symlink in place because rsync only manages
files inside `server/` and does not touch the top-level symlink. Re-run
the `ln -sfn` command if the symlink ever goes missing (idempotent).

## Why `server/` and not `scripts/`?

The repo already has `scripts/deploy.sh`, a developer-side rsync wrapper.
Adding a second `deploy.sh` under `scripts/` would collide and confuse
both humans and shell completion. Putting on-server entry points under
their own top-level directory makes the destination obvious and gives us
room to add other host-resident helpers later (e.g., `server/restore.sh`)
without crowding `scripts/`.

## Bashrc wrapper

A companion wrapper at
`config/bashrc/deploy.bashrc.d/00-block-docker-compose.sh` blocks bare
`docker compose` invocations under the `deploy` user's shell so an
operator cannot accidentally bypass `deploy.sh`. `deploy.sh` itself sets
`DEPLOY_SH_ALLOW_DOCKER=1` before each `docker compose` call, which the
wrapper checks before deciding whether to refuse.
