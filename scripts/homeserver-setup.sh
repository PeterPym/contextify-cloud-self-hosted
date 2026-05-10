#!/usr/bin/env bash
# homeserver-setup.sh
#
# Run this on the NEW MACHINE after initial macOS setup (Apple ID, macOS update).
# Assumes homeserver-secrets.env has been AirDropped to ~/Desktop/.
#
# Usage: bash ~/Desktop/homeserver-setup.sh
#
# Validation / rerun mode for an already-prepared host:
#   CONTEXTIFY_HOMESERVER_SKIP_SYSTEM_SETUP=1 \
#   CONTEXTIFY_HOMESERVER_HTTP_ONLY=1 \
#   CONTEXTIFY_HOMESERVER_NONINTERACTIVE=1 \
#   SELF_HOSTED_API_PORT=8444 \
#   REPO_DIR=~/contextify-validation/contextify-cloud \
#   GIT_REPO=file:///path/to/contextify-cloud.git \
#   GIT_BRANCH=ct1679-validation \
#   COMPOSE_PROJECT_NAME=contextify-validation \
#   SELF_HOSTED_PGDATA_VOLUME=contextify-validation-pgdata18 \
#   bash scripts/homeserver-setup.sh
#
# HTTPS prereq: enable MagicDNS and HTTPS certificates in Tailscale admin
# before running this script. Tailscale publishes the machine FQDN to the
# public certificate transparency ledger when issuing a *.ts.net cert.

set -euo pipefail

# SSH-launched non-login shells on macOS often miss Homebrew-managed tools.
# Seed the common paths before checking for brew, docker, tailscale, gh, or uv.
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

SECRETS_FILE="${SECRETS_FILE:-$HOME/Desktop/homeserver-secrets.env}"
REPO_DIR="${REPO_DIR:-$HOME/code/projects/contextify-cloud}"
GIT_REPO="${GIT_REPO:-git@github.com:banagale/contextify-cloud.git}"
GIT_BRANCH="${GIT_BRANCH:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.selfhosted.yml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"
SELF_HOSTED_PGDATA_VOLUME="${SELF_HOSTED_PGDATA_VOLUME:-}"
SELF_HOSTED_API_PORT="${SELF_HOSTED_API_PORT:-}"
CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT="${CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT:-$HOME/.cache/contextify-cloud/self-hosted-build-context}"
CONTEXTIFY_HOMESERVER_SKIP_SYSTEM_SETUP="${CONTEXTIFY_HOMESERVER_SKIP_SYSTEM_SETUP:-0}"
CONTEXTIFY_HOMESERVER_HTTP_ONLY="${CONTEXTIFY_HOMESERVER_HTTP_ONLY:-0}"
CONTEXTIFY_HOMESERVER_NONINTERACTIVE="${CONTEXTIFY_HOMESERVER_NONINTERACTIVE:-0}"

# Colors
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
step() { echo -e "\n${YELLOW}==>${NC} $*"; }
fail() { echo -e "${RED}[fail]${NC} $*"; exit 1; }

enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

pause_for_user() {
  local prompt="$1"
  if enabled "$CONTEXTIFY_HOMESERVER_NONINTERACTIVE"; then
    warn "Non-interactive mode: skipping prompt: $prompt"
    return 0
  fi
  read -r -p "$prompt"
}

compose() {
  local command=(docker compose)
  if [[ -n "$COMPOSE_PROJECT_NAME" ]]; then
    command+=(-p "$COMPOSE_PROJECT_NAME")
  fi
  command+=(-f "$COMPOSE_FILE" "$@")
  "${command[@]}"
}

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "Required command not found: $name"
}

port_in_use() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

describe_port() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
}

choose_api_port() {
  local requested="${SELF_HOSTED_API_PORT:-8443}"

  if [[ -n "$SELF_HOSTED_API_PORT" ]]; then
    if port_in_use "$requested"; then
      echo ""
      warn "Port $requested is already listening:" >&2
      describe_port "$requested" >&2
      fail "SELF_HOSTED_API_PORT=$requested is occupied. Stop that service or rerun with a different SELF_HOSTED_API_PORT."
    fi
    printf '%s\n' "$requested"
    return 0
  fi

  for port in 8443 8444 8445 8446 8447 8448 8449 8450; do
    if ! port_in_use "$port"; then
      if [[ "$port" != "8443" ]]; then
        echo "" >&2
        warn "Port 8443 is already listening, so Contextify Cloud will use loopback port $port." >&2
        if enabled "$CONTEXTIFY_HOMESERVER_HTTP_ONLY"; then
          warn "The HTTP-only Tailscale URL will include the selected port." >&2
        else
          warn "The public Tailscale URL remains unchanged because Caddy proxies HTTPS to the selected loopback port." >&2
        fi
      fi
      printf '%s\n' "$port"
      return 0
    fi
  done

  echo "" >&2
  warn "No free Contextify loopback API port found in 8443-8450." >&2
  warn "Current listeners:" >&2
  for port in 8443 8444 8445 8446 8447 8448 8449 8450; do
    describe_port "$port" >&2
  done
  fail "Free one of those ports or rerun with SELF_HOSTED_API_PORT=<free-port>."
}

echo ""
echo "================================================"
echo "  Contextify Homeserver Bootstrap"
echo "================================================"
echo ""

# Check secrets file exists
if [[ ! -f "$SECRETS_FILE" ]]; then
  fail "homeserver-secrets.env not found at $SECRETS_FILE\nAirDrop it from your dev machine first, then re-run."
fi
ok "Secrets file found"

if enabled "$CONTEXTIFY_HOMESERVER_SKIP_SYSTEM_SETUP"; then
  step "Phase 1-5: Reusing existing host prerequisites"
  require_command git
  require_command docker
  require_command tailscale
  require_command uv
  ok "Required commands found: git, docker, tailscale, uv"
else
  # -------------------------------------------------------
  # PHASE 1: Remote access (do this first, before anything else)
  # -------------------------------------------------------
  step "Phase 1: Enabling remote access"

  # SSH (Remote Login)
  sudo systemsetup -setremotelogin on 2>/dev/null && ok "Remote Login (SSH) enabled" || warn "systemsetup failed -- enable Remote Login manually in System Settings -> General -> Sharing"

  # Screen Sharing
  sudo launchctl enable system/com.apple.screensharing 2>/dev/null || true
  sudo launchctl kickstart -k system/com.apple.screensharing 2>/dev/null && ok "Screen Sharing enabled" || warn "Screen Sharing enable failed -- enable manually in System Settings -> General -> Sharing"

  # Power: never sleep, wake on network, auto-restart after power loss
  sudo pmset -a sleep 0 disksleep 0 displaysleep 0 womp 1 autorestart 1
  ok "Power settings configured (no sleep, wake on network)"

  MY_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "unknown")
  echo ""
  echo "  -----------------------------------------------"
  echo "  Remote access is now enabled."
  echo "  This machine's local IP: $MY_IP"
  echo "  From another machine on your network:"
  echo "    ssh $(whoami)@$MY_IP"
  echo "    Screen share: vnc://$(whoami)@$MY_IP"
  echo "  -----------------------------------------------"
  echo ""
  pause_for_user "  Test SSH from another machine now if you want, then press Enter to continue..."

  # -------------------------------------------------------
  # PHASE 2: Homebrew
  # -------------------------------------------------------
  step "Phase 2: Homebrew"

  if ! command -v brew &>/dev/null; then
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add to path for this session (Apple Silicon)
    eval "$(/opt/homebrew/bin/brew shellenv)"
    ok "Homebrew installed"
  else
    ok "Homebrew already installed"
  fi

  # Persist to shell config
  if ! grep -q "brew shellenv" ~/.zprofile 2>/dev/null; then
    printf '\n# Homebrew\nif [[ -x /opt/homebrew/bin/brew ]]; then eval "$(/opt/homebrew/bin/brew shellenv)"; fi\n' >> ~/.zprofile
  fi
  if ! grep -q "brew shellenv" ~/.zshrc 2>/dev/null; then
    printf '\n# Homebrew\nif [[ -x /opt/homebrew/bin/brew ]]; then eval "$(/opt/homebrew/bin/brew shellenv)"; fi\n' >> ~/.zshrc
  fi

  # -------------------------------------------------------
  # PHASE 3: Core tools
  # -------------------------------------------------------
  step "Phase 3: Installing tools"

  brew install git gh uv caddy
  brew install --cask orbstack tailscale
  ok "git, gh, uv, Caddy, OrbStack, Tailscale installed"

  warn "Skipping global Git identity changes. Configure Git manually if you plan to commit from this host."

  # -------------------------------------------------------
  # PHASE 4: SSH keys
  # -------------------------------------------------------
  step "Phase 4: SSH keys"

  if [[ -f "$HOME/Desktop/dot-ssh/banagale.com_ed25519" ]]; then
    mkdir -p ~/.ssh
    cp -R "$HOME/Desktop/dot-ssh/"* ~/.ssh/
    chmod 700 ~/.ssh
    chmod 600 ~/.ssh/*
    chmod 644 ~/.ssh/*.pub 2>/dev/null || true
    chmod 644 ~/.ssh/config 2>/dev/null || true
    ssh-add --apple-use-keychain ~/.ssh/banagale.com_ed25519 2>/dev/null || true
    ok "SSH keys installed"
  else
    warn "No dot-ssh folder found on Desktop. Skipping SSH key install."
    warn "To get GitHub access you will need to either:"
    warn "  - AirDrop dot-ssh from your dev machine and re-run, OR"
    warn "  - Generate a new key: ssh-keygen -t ed25519 -C 'homeserver' -f ~/.ssh/homeserver_ed25519"
    warn "    Then add the public key at https://github.com/settings/keys"
  fi

  # -------------------------------------------------------
  # PHASE 5: Tailscale
  # -------------------------------------------------------
  step "Phase 5: Tailscale"

  echo ""
  echo "  Starting Tailscale -- a browser window will open for authentication."
  echo "  Sign in with the same account used on your other machines."
  echo ""
  open -a Tailscale 2>/dev/null || warn "Open Tailscale from Applications to authenticate"
  pause_for_user "  Press Enter once Tailscale is authenticated and this machine appears in your tailnet..."
fi

TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [[ -n "$TAILSCALE_IP" ]]; then
  ok "Tailscale connected: $TAILSCALE_IP"
else
  warn "Could not detect Tailscale IP. Check Tailscale status after setup."
  TAILSCALE_IP="<tailscale-ip>"
fi

TAILSCALE_HOST=$(tailscale status --json 2>/dev/null | awk -F'"' 'BEGIN { in_self = 0 } /"Self":/ { in_self = 1 } in_self && /"DNSName"/ { print $4; exit }' | sed 's/[.]$//')
if [[ -n "$TAILSCALE_HOST" ]]; then
  ok "Tailscale MagicDNS host: $TAILSCALE_HOST"
else
  fail "Could not detect Tailscale DNSName. Enable MagicDNS in Tailscale, confirm this machine has a *.ts.net name, then re-run."
fi

# -------------------------------------------------------
# PHASE 6: contextify-cloud
# -------------------------------------------------------
step "Phase 6: contextify-cloud"

# Wait for OrbStack (Docker) to be ready
echo "  Waiting for OrbStack/Docker to be ready..."
for i in {1..30}; do
  docker info &>/dev/null && break || sleep 2
  if (( i == 1 || i % 5 == 0 )); then
    echo "  Still waiting for Docker... elapsed about $((i * 2))s of 60s"
  fi
  [[ $i -eq 30 ]] && fail "Docker not ready after 60s. Open OrbStack from Applications and wait for it to start, then re-run from Phase 6."
done
ok "Docker ready"

# Clone repo
mkdir -p "$(dirname "$REPO_DIR")"
if [[ -d "$REPO_DIR/.git" ]]; then
  warn "Repo already exists at $REPO_DIR -- pulling latest"
  if [[ -n "$GIT_BRANCH" ]]; then
    git -C "$REPO_DIR" fetch origin "$GIT_BRANCH"
    git -C "$REPO_DIR" checkout "$GIT_BRANCH"
    git -C "$REPO_DIR" pull --ff-only origin "$GIT_BRANCH"
  else
    git -C "$REPO_DIR" pull --ff-only
  fi
else
  if [[ -e "$REPO_DIR" ]]; then
    fail "REPO_DIR exists but is not a Git checkout: $REPO_DIR"
  fi
  if [[ -n "$GIT_BRANCH" ]]; then
    git clone --branch "$GIT_BRANCH" "$GIT_REPO" "$REPO_DIR"
  else
    git clone "$GIT_REPO" "$REPO_DIR"
  fi
  ok "Repo cloned"
fi
REPO_REVISION=$(git -C "$REPO_DIR" rev-parse --short HEAD)
ok "Repo ready at revision: ${REPO_REVISION}"

# Write .env from secrets file.
# Per ct-683, EMAIL_BASE_URL and INVITATION_BASE_URL must be set to the
# self-hosted server URL. The boot guard rejects empty values and rejects
# any URL pointing at cloud.contextify.sh while SELF_HOSTED=true.
source "$SECRETS_FILE"

if [[ -z "${TAILSCALE_IP:-}" || "$TAILSCALE_IP" == "<tailscale-ip>" ]]; then
  fail "TAILSCALE_IP unresolved. Authenticate Tailscale (Phase 5) and re-run from Phase 6."
fi

SELF_HOSTED_API_PORT="$(choose_api_port)"
LOCAL_API_URL="http://127.0.0.1:${SELF_HOSTED_API_PORT}"
if enabled "$CONTEXTIFY_HOMESERVER_HTTP_ONLY"; then
  SERVER_URL="http://${TAILSCALE_HOST}:${SELF_HOSTED_API_PORT}"
  API_BIND_HOST="${BIND_HOST:-0.0.0.0}"
  FORCE_SECURE_COOKIES_DEFAULT=false
else
  SERVER_URL="https://${TAILSCALE_HOST}"
  API_BIND_HOST="${BIND_HOST:-127.0.0.1}"
  FORCE_SECURE_COOKIES_DEFAULT=true
fi
SETUP_TOKEN="${CONTEXTIFY_SELF_HOSTED_SETUP_TOKEN:-$(openssl rand -hex 24)}"
if [[ -z "$SELF_HOSTED_PGDATA_VOLUME" ]]; then
  if [[ -n "$COMPOSE_PROJECT_NAME" ]]; then
    SELF_HOSTED_PGDATA_VOLUME="${COMPOSE_PROJECT_NAME}_pgdata18"
  else
    SELF_HOSTED_PGDATA_VOLUME="contextify-cloud_selfhosted_pgdata18"
  fi
fi
ok "Selected loopback API port: ${SELF_HOSTED_API_PORT}"
ok "API bind host: ${API_BIND_HOST}"
ok "PostgreSQL volume: ${SELF_HOSTED_PGDATA_VOLUME}"

export CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT
echo "  Generating Personal Self-Hosted build context outside the private checkout..."
(
  cd "$REPO_DIR"
  uv run python scripts/export_self_hosted.py --output "$CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT"
)
ok "Personal build context ready: ${CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT}"

cat > "$REPO_DIR/.env" <<EOF
# contextify-cloud .env (homeserver, generated by homeserver-setup.sh)
# DO NOT commit this file. Run \`bash scripts/gen-homeserver-secrets.sh\` on
# your dev machine to refresh secrets if you need to rotate.

# --- Identity / mode ---
SELF_HOSTED=${SELF_HOSTED:-true}
CONTEXTIFY_SELF_HOSTED_SETUP_TOKEN=${SETUP_TOKEN}

# --- Secrets (transferred from dev machine) ---
DB_PASSWORD=${DB_PASSWORD}
API_SECRET_KEY=${API_SECRET_KEY}

# --- Self-hosted URLs (auto-derived from Tailscale IP) ---
# Both must be set so verification, magic-link, password-reset, and
# invitation emails embed links pointing at this server.
EMAIL_BASE_URL=${SERVER_URL}
INVITATION_BASE_URL=${SERVER_URL}

# --- Network binding ---
# docker-compose.selfhosted.yml defaults BIND_HOST to loopback for manual runs.
# The blessed self-hosted ingress path is host-level Caddy on 443 proxying to
# a loopback-bound API. HTTP-only validation mode binds to all host interfaces
# unless BIND_HOST overrides it, and should only be used on trusted networks.
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME}
BIND_HOST=${API_BIND_HOST}
SELF_HOSTED_API_PORT=${SELF_HOSTED_API_PORT}
SELF_HOSTED_PGDATA_VOLUME=${SELF_HOSTED_PGDATA_VOLUME}
CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT=${CONTEXTIFY_SELF_HOSTED_BUILD_CONTEXT}

# --- CORS ---
ALLOWED_ORIGINS=http://localhost:3000,${SERVER_URL}

# --- Logging ---
LOG_LEVEL=${LOG_LEVEL:-info}
LOG_FORMAT=${LOG_FORMAT:-text}

# --- Optional: transactional email (Resend) ---
# Leave empty to log auth emails to the api container instead of sending.
# Personal SH typically uses log-only delivery; \`docker compose -f ${COMPOSE_FILE} logs api | grep -i email\`
# surfaces verification, password-reset, and magic-link links.
RESEND_API_KEY=
EMAIL_FROM=noreply@contextify.sh
EMAIL_REPLY_TO=support@contextify.sh

# --- Optional: SMTP fallback for invitations (separate from RESEND) ---
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=noreply@contextify.sh

# --- Optional: error monitoring (Sentry) ---
ERROR_MONITORING_ENABLED=false
SENTRY_DSN=
SENTRY_ENVIRONMENT=self-hosted

# --- Optional: ops tokens (only set if you expose ops endpoints externally) ---
OPS_SMOKE_TOKEN=
SUPPORT_ADMIN_TOKEN=

# --- Registration / docs (defaults are SH-friendly) ---
ENABLE_REGISTRATION=${ENABLE_REGISTRATION:-true}
ENABLE_DOCS=${ENABLE_DOCS:-false}

# --- Cookies ---
# Host-level Caddy terminates HTTPS and forwards to the loopback API, so browser
# sessions should always use Secure cookies in the blessed self-hosted path.
FORCE_SECURE_COOKIES=${FORCE_SECURE_COOKIES:-${FORCE_SECURE_COOKIES_DEFAULT}}
TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS:-172.16.0.0/12,198.19.0.0/16}

# --- Data retention (0 disables auto-purge for personal use) ---
DEFAULT_DATA_RETENTION_DAYS=0
PURGE_GRACE_PERIOD_DAYS=30
PURGE_TOMBSTONE_RETENTION_MONTHS=12
EOF
chmod 600 "$REPO_DIR/.env"
ok ".env written (server URL: ${SERVER_URL})"

# Start the stack
cd "$REPO_DIR"
echo "  Building and starting the Docker stack. First runs can take several minutes while images build."
compose up -d --build
ok "Docker stack started"

# -------------------------------------------------------
# PHASE 7: Health check
# -------------------------------------------------------
step "Phase 7: Health check"

echo "  Waiting for server to be ready..."
for i in {1..20}; do
  HEALTH=$(curl -sf "${LOCAL_API_URL}/api/v1/health" 2>/dev/null || echo "")
  if echo "$HEALTH" | grep -q "ok"; then
    ok "Server healthy on loopback: $HEALTH"
    break
  fi
  sleep 3
  if (( i == 1 || i % 5 == 0 )); then
    echo "  Still waiting for API health... elapsed about $((i * 3))s of 60s"
  fi
  [[ $i -eq 20 ]] && fail "Server did not become healthy. Check logs: docker compose -f $COMPOSE_FILE logs -f api"
done

step "Phase 8: HTTPS ingress"

if enabled "$CONTEXTIFY_HOMESERVER_HTTP_ONLY"; then
  warn "HTTP-only mode is enabled. Skipping Tailscale certificate and Caddy configuration."
  warn "Use this only for local validation or until the HTTPS backlog item lands."
  if [[ "$API_BIND_HOST" == "0.0.0.0" ]]; then
    warn "HTTP-only mode exposes the API on all host interfaces at port ${SELF_HOSTED_API_PORT}. Use only on a trusted network or set BIND_HOST explicitly."
  fi
  HTTP_HEALTH=$(curl -sf "${SERVER_URL}/api/v1/health" 2>/dev/null || echo "")
  if echo "$HTTP_HEALTH" | grep -q "ok"; then
    ok "Server healthy on HTTP Tailscale URL: ${SERVER_URL}"
  elif [[ -n "${TAILSCALE_IP:-}" && "$TAILSCALE_IP" != "<tailscale-ip>" ]]; then
    IP_SERVER_URL="http://${TAILSCALE_IP}:${SELF_HOSTED_API_PORT}"
    IP_HEALTH=$(curl -sf "${IP_SERVER_URL}/api/v1/health" 2>/dev/null || echo "")
    if echo "$IP_HEALTH" | grep -q "ok"; then
      warn "MagicDNS URL did not resolve from this host, but Tailscale IP health passed."
      warn "Verify ${SERVER_URL}/api/v1/health from another tailnet device. If local MagicDNS is needed here, toggle Tailscale DNS with: tailscale set --accept-dns=false && tailscale set --accept-dns=true"
      ok "Server healthy on Tailscale IP URL: ${IP_SERVER_URL}"
    else
      fail "Server did not respond on ${SERVER_URL}/api/v1/health or ${IP_SERVER_URL}/api/v1/health. Confirm the selected port is reachable over the tailnet and BIND_HOST is not loopback-only."
    fi
  else
    fail "Server did not respond on ${SERVER_URL}/api/v1/health. Confirm the selected port is reachable over the tailnet and BIND_HOST is not loopback-only."
  fi
else

CERT_DIR="$HOME/.config/contextify-cloud/tls"
CERT_FILE="$CERT_DIR/${TAILSCALE_HOST}.crt"
KEY_FILE="$CERT_DIR/${TAILSCALE_HOST}.key"
CADDYFILE="$(brew --prefix)/etc/Caddyfile"

mkdir -p "$CERT_DIR"
chmod 700 "$HOME/.config/contextify-cloud" "$CERT_DIR"

echo "  Requesting Tailscale HTTPS certificate for ${TAILSCALE_HOST}..."
if tailscale cert --cert-file "$CERT_FILE" --key-file "$KEY_FILE" "$TAILSCALE_HOST"; then
  ok "Tailscale certificate written"
else
  warn "tailscale cert failed as current user; retrying with sudo"
  sudo tailscale cert --cert-file "$CERT_FILE" --key-file "$KEY_FILE" "$TAILSCALE_HOST"
  ok "Tailscale certificate written with sudo"
fi
chmod 644 "$CERT_FILE"
chmod 600 "$KEY_FILE"

# TS_PERMIT_CERT_UID is not required for this MVP topology because Caddy reads
# certificate files generated by `tailscale cert` instead of calling tailscaled
# for certificates at TLS handshake time. If this moves to Caddy's native
# Tailscale issuer later, set TS_PERMIT_CERT_UID for the Caddy service user first.
tmp_caddyfile="$(mktemp)"
cat > "$tmp_caddyfile" <<EOF
${TAILSCALE_HOST} {
  encode zstd gzip
  reverse_proxy 127.0.0.1:${SELF_HOSTED_API_PORT} {
    header_up Host {host}
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto https
  }
  tls ${CERT_FILE} ${KEY_FILE}
  header Strict-Transport-Security "max-age=31536000"
}
EOF
sudo mkdir -p "$(dirname "$CADDYFILE")"
if sudo test -f "$CADDYFILE"; then
  CADDYFILE_BACKUP="${CADDYFILE}.bak.$(date +%Y%m%d%H%M%S)"
  sudo cp "$CADDYFILE" "$CADDYFILE_BACKUP"
  ok "Existing Caddyfile backed up to $CADDYFILE_BACKUP"
fi
sudo cp "$tmp_caddyfile" "$CADDYFILE"
rm -f "$tmp_caddyfile"
sudo caddy validate --config "$CADDYFILE"
sudo brew services restart caddy
ok "Caddy configured and restarted"

HTTPS_HEALTH=$(curl -sf "${SERVER_URL}/api/v1/health" 2>/dev/null || echo "")
if echo "$HTTPS_HEALTH" | grep -q "ok"; then
  ok "Server healthy on HTTPS Tailscale URL: ${SERVER_URL}"
else
  fail "Server did not respond on ${SERVER_URL}/api/v1/health. Verify Tailscale HTTPS certificates are enabled, Caddy is running, and port 443 is reachable from your tailnet."
fi
fi

# -------------------------------------------------------
# Done
# -------------------------------------------------------
COMPOSE_DISPLAY="docker compose"
if [[ -n "$COMPOSE_PROJECT_NAME" ]]; then
  COMPOSE_DISPLAY="${COMPOSE_DISPLAY} -p ${COMPOSE_PROJECT_NAME}"
fi
COMPOSE_DISPLAY="${COMPOSE_DISPLAY} -f ${COMPOSE_FILE}"

echo ""
echo "================================================"
echo -e "${GREEN}  Homeserver setup complete!${NC}"
echo "================================================"
echo ""
echo "  Local:     ${LOCAL_API_URL}/api/v1/health"
echo "  Tailscale: ${SERVER_URL}/api/v1/health"
echo ""
echo "  First admin setup:"
echo "    Open ${SERVER_URL}/setup?token=${SETUP_TOKEN}"
echo "    or run: cd $REPO_DIR && $COMPOSE_DISPLAY exec api python -m contextify_cloud create-admin --email you@example.com"
if ! enabled "$CONTEXTIFY_HOMESERVER_HTTP_ONLY"; then
  echo ""
  echo "  TLS renewal:"
  echo "    tailscale cert --cert-file $CERT_FILE --key-file $KEY_FILE $TAILSCALE_HOST"
  echo "    sudo caddy reload --config $CADDYFILE"
fi
echo ""
echo "  Backups:"
echo "    cd $REPO_DIR && scripts/contextify-cloud-selfhosted backup --compose-file $COMPOSE_FILE --output-dir \"\$HOME/Library/Application Support/ContextifyCloud/backups\""
echo "    cd $REPO_DIR && scripts/contextify-cloud-selfhosted launchd-plist --repo-dir $REPO_DIR --compose-file $COMPOSE_FILE --output-dir \"\$HOME/Library/Application Support/ContextifyCloud/backups\" --output \"\$HOME/Library/LaunchAgents/com.contextify.cloud.backup.plist\""
echo "    launchctl bootstrap \"gui/\$(id -u)\" \"\$HOME/Library/LaunchAgents/com.contextify.cloud.backup.plist\""
echo ""
echo "  Updates:"
echo "    cd $REPO_DIR && scripts/contextify-cloud-selfhosted update --repo-dir $REPO_DIR --compose-file $COMPOSE_FILE --backup-dir \"\$HOME/Library/Application Support/ContextifyCloud/backups\" --health-url \"http://127.0.0.1:${SELF_HOSTED_API_PORT}/api/v1/health\""
echo "    cd $REPO_DIR && scripts/contextify-cloud-selfhosted launchd-plist --job update --repo-dir $REPO_DIR --compose-file $COMPOSE_FILE --output-dir \"\$HOME/Library/Application Support/ContextifyCloud/backups\" --health-url \"http://127.0.0.1:${SELF_HOSTED_API_PORT}/api/v1/health\" --output \"\$HOME/Library/LaunchAgents/com.contextify.cloud.update.plist\""
echo ""
echo "  Next -- on your dev machine:"
echo "    contextify cloud setup --url ${SERVER_URL}"
echo "    contextify cloud status"
echo "    contextify cloud push"
echo ""
echo "  Logs: cd $REPO_DIR && $COMPOSE_DISPLAY logs -f api"
echo "  Restart: cd $REPO_DIR && $COMPOSE_DISPLAY restart"
echo ""
