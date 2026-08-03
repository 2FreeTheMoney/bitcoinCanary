#!/usr/bin/env bash
# canaryEW deployment for Debian-family systems. Run as root from the repo root:
#   sudo deploy/deploy.sh
#
# Idempotent: safe to re-run for upgrades. Never touches the sealed store,
# the boot file, or /etc/canaryew/canaryew.env once they exist.

set -euo pipefail

APP_DIR=/opt/canaryew
STATE_DIR=/var/lib/canaryew
ENV_DIR=/etc/canaryew
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "== users and groups =="
id -u canaryew >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" \
    --shell /usr/sbin/nologin canaryew
id -u canaryew-web >/dev/null 2>&1 || useradd --system --no-create-home \
    --shell /usr/sbin/nologin --groups canaryew canaryew-web
# Read access to bitcoind's RPC cookie:
if getent group bitcoin >/dev/null 2>&1; then
    usermod -aG bitcoin canaryew
else
    echo "  NOTE: no 'bitcoin' group found. Grant canaryew read access to the"
    echo "  RPC cookie file yourself (CANARYEW_RPC_COOKIE_FILE)."
fi

echo "== directories =="
install -d -o canaryew -g canaryew -m 0750 "$STATE_DIR"
install -d -o root -g canaryew -m 0750 "$ENV_DIR"

echo "== application =="
# State the source and a content fingerprint: deploy.sh copies from its own
# directory, so running an old copy of this script silently redeploys old
# code. The fingerprint makes that visible instead of mysterious.
SRC_SUM="$(find "$REPO_DIR/src" -type f -name '*.py' -exec sha256sum {} + \
    | sort | sha256sum | cut -c1-12)"
echo "  source:      $REPO_DIR"
echo "  src digest:  $SRC_SUM"
install -d -m 0755 "$APP_DIR"
# Replace, never merge: a cp -R over an existing tree would leave files that
# upstream deleted or renamed, and a stale module shadowing a new one is a
# miserable bug to find. The venv is preserved.
rm -rf "$APP_DIR/src" "$APP_DIR/docs"
cp -R "$REPO_DIR/src" "$APP_DIR/"
cp -R "$REPO_DIR/docs" "$APP_DIR/"
rm -f "$APP_DIR/docs/PRIVATE-NOTES.md"   # never belongs outside the dev machine
cp "$REPO_DIR/pyproject.toml" "$REPO_DIR/README.md" "$APP_DIR/"
if [ ! -d "$APP_DIR/.venv" ]; then
    python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet "$APP_DIR"

echo "== configuration =="
if [ ! -f "$ENV_DIR/canaryew.env" ]; then
    install -o root -g canaryew -m 0640 \
        "$REPO_DIR/deploy/canaryew.env.example" "$ENV_DIR/canaryew.env"
    echo "  Wrote $ENV_DIR/canaryew.env -- EDIT IT before starting the service."
else
    echo "  Keeping existing $ENV_DIR/canaryew.env"
fi

echo "== systemd =="
install -m 0644 "$REPO_DIR/deploy/canaryew.service" /etc/systemd/system/
install -m 0644 "$REPO_DIR/deploy/canaryew-web.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable canaryew.service canaryew-web.service

# Deliberately no automatic restart: bouncing a security monitor is the
# operator's call, made when they are ready to unlock immediately after.
if systemctl is-active --quiet canaryew.service; then
    echo
    echo "  *** canaryew is RUNNING and still executing the OLD code. ***"
    echo "  Pick up this deploy with:"
    echo "      sudo systemctl restart canaryew canaryew-web"
    echo "  then unlock (the service comes back LOCKED and will say so):"
    echo "      sudo -u canaryew /opt/canaryew/.venv/bin/canaryew unlock"
fi

cat <<'EOF'

Deployed. Next steps (see docs/RUNBOOK.md for the full walkthrough):

  1. Edit /etc/canaryew/canaryew.env  (the CLI reads it too, not just systemd)
  2. sudo -u canaryew /opt/canaryew/.venv/bin/canaryew init
  3. Enroll on your trusted machine, copy the watchfile over, import it here
  4. sudo systemctl start canaryew canaryew-web
  5. sudo -u canaryew /opt/canaryew/.venv/bin/canaryew unlock
EOF
