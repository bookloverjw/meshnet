#!/usr/bin/env bash
# setup-relay.sh — One-shot relay server setup for AlmaLinux 9 VPS
# Usage: scp this script + meshd-linux-amd64 to the VPS, then run as root.
set -euo pipefail

RELAY_BIN="meshd-linux-amd64"
INSTALL_DIR="/opt/meshnet"
DOMAIN=""  # Set this if you have a domain pointed at the VPS

# ── Check root ──────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run this script as root."
  exit 1
fi

# ── Check binary exists ────────────────────────────────────────────
if [ ! -f "./$RELAY_BIN" ]; then
  echo "ERROR: $RELAY_BIN not found in current directory."
  echo "Upload it alongside this script first."
  exit 1
fi

echo "==> Setting up meshnet relay server..."

# ── Install dir ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cp "./$RELAY_BIN" "$INSTALL_DIR/meshd"
chmod +x "$INSTALL_DIR/meshd"
echo "    Installed meshd to $INSTALL_DIR/meshd"

# ── Generate auth token ───────────────────────────────────────────
TOKEN_FILE="$INSTALL_DIR/auth-token"
if [ ! -f "$TOKEN_FILE" ]; then
  TOKEN=$(openssl rand -hex 32)
  echo "$TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  echo "    Generated auth token → $TOKEN_FILE"
else
  TOKEN=$(cat "$TOKEN_FILE")
  echo "    Using existing auth token from $TOKEN_FILE"
fi

# ── Firewall ───────────────────────────────────────────────────────
echo "==> Configuring firewall..."
firewall-cmd --permanent --add-port=443/tcp  2>/dev/null || true
firewall-cmd --permanent --add-port=80/tcp   2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true
echo "    Opened ports 80 and 443"

# ── Optional: Let's Encrypt (if domain is set) ────────────────────
CERT_FLAGS=""
if [ -n "$DOMAIN" ]; then
  echo "==> Setting up Let's Encrypt for $DOMAIN..."
  dnf install -y epel-release
  dnf install -y certbot
  certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email
  CERT_FLAGS="--cert /etc/letsencrypt/live/$DOMAIN/fullchain.pem --key /etc/letsencrypt/live/$DOMAIN/privkey.pem"
  echo "    TLS certificates installed"
fi

# ── Systemd service ───────────────────────────────────────────────
cat > /etc/systemd/system/meshnet-relay.service <<UNIT
[Unit]
Description=Meshnet Relay Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/meshd --addr :443 --token \${MESHNET_AUTH_TOKEN} $CERT_FLAGS
EnvironmentFile=$INSTALL_DIR/env
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

# ── Environment file ──────────────────────────────────────────────
cat > "$INSTALL_DIR/env" <<ENV
MESHNET_AUTH_TOKEN=$TOKEN
ENV
chmod 600 "$INSTALL_DIR/env"

# ── Enable and start ─────────────────────────────────────────────
systemctl daemon-reload
systemctl enable meshnet-relay
systemctl start meshnet-relay

echo ""
echo "=========================================="
echo "  Meshnet relay is LIVE"
echo "=========================================="
echo "  Address:  0.0.0.0:443"
echo "  Auth token: $TOKEN"
echo ""
echo "  SAVE THIS TOKEN — your clients need it."
echo ""
echo "  Check status:  systemctl status meshnet-relay"
echo "  View logs:     journalctl -u meshnet-relay -f"
echo "=========================================="
