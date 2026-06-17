#!/usr/bin/env bash
# AuditForwarder - install.sh
# Installs the auditforwarder agent on Linux systems.
#
# Usage: sudo ./install.sh [options]
#   --prefix PATH        Install prefix (default: /usr/local)
#   --etcdir PATH        Configuration directory (default: /etc/auditforwarder)
#   --datadir PATH       Data directory (default: /var/lib/auditforwarder)
#   --logdir PATH        Log directory (default: /var/log/auditforwarder)
#   --no-systemd         Skip systemd service installation
#   --no-keys            Skip generation of a new Ed25519 key pair
#   --start              Start the service after installation
#   --uninstall          Uninstall the agent

set -euo pipefail

PREFIX="/usr/local"
ETCDIR="/etc/auditforwarder"
DATADIR="/var/lib/auditforwarder"
LOGDIR="/var/log/auditforwarder"
USE_SYSTEMD=1
GENERATE_KEYS=1
START=0
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2;;
        --etcdir)     ETCDIR="$2"; shift 2;;
        --datadir)    DATADIR="$2"; shift 2;;
        --logdir)     LOGDIR="$2"; shift 2;;
        --no-systemd) USE_SYSTEMD=0; shift;;
        --no-keys)    GENERATE_KEYS=0; shift;;
        --start)      START=1; shift;;
        --uninstall)  UNINSTALL=1; shift;;
        -h|--help)    sed -n '2,16p' "$0"; exit 0;;
        *)            echo "Unknown option: $1" >&2; exit 2;;
    esac
done

BIN="$PREFIX/bin/auditforwarderd"

uninstall() {
    echo "[uninstall] stopping service..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop    auditforwarder.service 2>/dev/null || true
        systemctl disable auditforwarder.service 2>/dev/null || true
        rm -f /etc/systemd/system/auditforwarder.service
        systemctl daemon-reload
    fi
    echo "[uninstall] removing binaries..."
    rm -f "$BIN"
    rm -rf "$PREFIX/share/auditforwarder"
    echo "[uninstall] data, logs and config left in place at:"
    echo "  $ETCDIR  $DATADIR  $LOGDIR"
    echo "  remove with:  rm -rf $ETCDIR $DATADIR $LOGDIR"
    echo "AuditForwarder uninstalled."
}

if [ "$UNINSTALL" = "1" ]; then
    uninstall
    exit 0
fi

# ---- preflight ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
fi

echo "[install] prefix=$PREFIX  etc=$ETCDIR  data=$DATADIR  log=$LOGDIR"

# ---- binary ---------------------------------------------------------------
if [ ! -x "$BIN" ]; then
    SRC_BIN="$(cd "$(dirname "$0")" && pwd)/../build/auditforwarderd"
    if [ ! -x "$SRC_BIN" ]; then
        echo "Error: binary not found at $BIN or $SRC_BIN" >&2
        echo "Build the project first: cmake -S . -B build && cmake --build build -j" >&2
        exit 1
    fi
    install -d "$PREFIX/bin"
    install -m 0755 "$SRC_BIN" "$BIN"
    echo "[install] installed $BIN"
fi

# ---- config dirs ----------------------------------------------------------
install -d -m 0750 "$ETCDIR" "$ETCDIR/keys" "$ETCDIR/tls"
install -d -m 0750 "$DATADIR" "$DATADIR/batches"
install -d -m 0750 "$LOGDIR"

# ---- default config -------------------------------------------------------
if [ ! -f "$ETCDIR/agent.yaml" ]; then
    install -m 0640 "$(dirname "$0")/../config/agent.yaml" "$ETCDIR/agent.yaml"
    sed -i "s|/etc/auditforwarder|$ETCDIR|g; s|/var/lib/auditforwarder|$DATADIR|g; s|/var/log/auditforwarder|$LOGDIR|g" "$ETCDIR/agent.yaml"
fi
if [ ! -f "$ETCDIR/rules.yaml" ]; then
    install -m 0640 "$(dirname "$0")/../config/rules.yaml" "$ETCDIR/rules.yaml"
fi

# ---- keys -----------------------------------------------------------------
if [ "$GENERATE_KEYS" = "1" ] && [ ! -f "$ETCDIR/keys/agent.pem" ]; then
    if command -v openssl >/dev/null 2>&1; then
        echo "[install] generating Ed25519 signing key..."
        openssl genpkey -algorithm ed25519 -out "$ETCDIR/keys/agent.pem" 2>/dev/null
        openssl pkey -in "$ETCDIR/keys/agent.pem" -pubout -out "$ETCDIR/keys/agent.pub"
        chmod 0640 "$ETCDIR/keys/agent.pem" "$ETCDIR/keys/agent.pub"
        echo "[install] keys written to $ETCDIR/keys/"
    else
        echo "[install] openssl not found; using HMAC fallback"
    fi
fi

# ---- TLS bootstrap --------------------------------------------------------
if [ ! -f "$ETCDIR/tls/client.crt" ]; then
    echo "[install] generating self-signed client cert (replace in production)"
    openssl req -x509 -newkey ed25519 -nodes -days 3650 \
        -keyout "$ETCDIR/tls/client.key" -out "$ETCDIR/tls/client.crt" \
        -subj "/CN=auditforwarder-$(hostname)" 2>/dev/null || true
    chmod 0600 "$ETCDIR/tls/client.key"
    chmod 0644 "$ETCDIR/tls/client.crt"
    # also use as the CA for now
    cp "$ETCDIR/tls/client.crt" "$ETCDIR/tls/ca.crt"
fi

# ---- systemd --------------------------------------------------------------
if [ "$USE_SYSTEMD" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/auditforwarder.service <<EOF
[Unit]
Description=AuditForwarder Security Audit Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -c $ETCDIR/agent.yaml -d $DATADIR
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
CapabilityBoundingSet=CAP_AUDIT_READ CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
AmbientCapabilities=CAP_AUDIT_READ CAP_DAC_READ_SEARCH
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 /etc/systemd/system/auditforwarder.service
    systemctl daemon-reload
    if [ "$START" = "1" ]; then
        systemctl enable --now auditforwarder.service
    fi
    echo "[install] systemd service installed."
fi

# ---- capabilities ---------------------------------------------------------
# If running as non-root and libaudit is in use, the user/group will need
# CAP_AUDIT_READ.  The systemd unit already grants it.
echo
echo "AuditForwarder installed successfully."
echo "  Binary:    $BIN"
echo "  Config:    $ETCDIR/agent.yaml"
echo "  Rules:     $ETCDIR/rules.yaml"
echo "  Keys:      $ETCDIR/keys/agent.pem"
echo "  Data:      $DATADIR"
echo "  Logs:      $LOGDIR"
[ "$USE_SYSTEMD" = "1" ] && echo
[ "$USE_SYSTEMD" = "1" ] && echo "  Manage with:  sudo systemctl {start|stop|status} auditforwarder"
[ "$USE_SYSTEMD" = "1" ] && echo "  View logs:    sudo journalctl -u auditforwarder -f"
