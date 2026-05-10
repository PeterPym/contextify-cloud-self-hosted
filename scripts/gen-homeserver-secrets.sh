#!/usr/bin/env bash
# gen-homeserver-secrets.sh
#
# Run this on your DEV machine before homeserver setup day.
# Generates a homeserver-secrets.env file ready to AirDrop to the new machine.
#
# Scope (per ct-683): this file ONLY transports secrets that must come from
# the dev machine -- random API/DB credentials. Non-secret config
# (EMAIL_BASE_URL, INVITATION_BASE_URL, ALLOWED_ORIGINS,
# logging, retention, etc.) is computed and written to .env on the homeserver
# by homeserver-setup.sh because those values depend on the homeserver's
# Tailscale IP, which only resolves on the destination machine.
#
# Usage: bash scripts/gen-homeserver-secrets.sh

set -euo pipefail

CLOUD_ENV="$HOME/code/projects/contextify-cloud/.env"
OUT="$HOME/Desktop/homeserver-secrets.env"

echo "Generating homeserver secrets..."

# Generate random secrets. API_SECRET_KEY MUST be unique per install --
# validate_runtime_settings() refuses to boot with the in-tree default
# (`dev-secret-change-me`) in either hosted or self-hosted mode (ct-683).
API_SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 20)

if [[ ! -f "$CLOUD_ENV" ]]; then
  echo "  $CLOUD_ENV not found -- Stripe keys left blank (fine for SH personal use)."
fi

cat > "$OUT" <<EOF
# contextify-cloud homeserver secrets
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)
# Transfer via AirDrop to ~/Desktop/ on new machine before running homeserver-setup.sh.
# homeserver-setup.sh will source this file and write the full .env with
# the homeserver-resolved Tailscale URL set as EMAIL_BASE_URL / INVITATION_BASE_URL.

# Required secrets
DB_PASSWORD=${DB_PASSWORD}
API_SECRET_KEY=${API_SECRET_KEY}

# Mode
SELF_HOSTED=true
LOG_LEVEL=info
EOF

chmod 600 "$OUT"

echo ""
echo "Done. Secrets written to: $OUT"
echo ""
echo "Next steps:"
echo "  1. AirDrop $OUT to ~/Desktop/ on the new machine"
echo "  2. AirDrop scripts/homeserver-setup.sh to ~/Desktop/ on the new machine"
echo "  3. On the new machine, open Terminal and run:"
echo "       bash ~/Desktop/homeserver-setup.sh"
