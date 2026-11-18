#!/bin/sh
# Sentinel installer for Linux (systemd), no Docker needed.
#
#   curl -fsSL https://raw.githubusercontent.com/TheFirstTerminal/sentinel/main/deploy/install.sh | sudo sh
#
# Options (environment variables, e.g. `| sudo UPSTREAM=http://localhost:3000 sh`):
#   UPSTREAM          your app, written into a new config file (default http://localhost:3000)
#   SENTINEL_VERSION  a version like 0.13.0 (default: the latest release)
#
# What it does: downloads the binary for this machine from the GitHub
# release, checks it against the release's checksums (and their signature
# when cosign is installed), installs it as /usr/local/bin/sentinel, creates
# a `sentinel` system user, writes /etc/sentinel/sentinel.yaml if there is
# none, and starts the `sentinel` systemd service. Running it again updates
# the binary and keeps your config and data.
#
# Copyright (c) 2026 Saif Zahid. Licensed under PolyForm Shield 1.0.0.
set -eu

REPO=TheFirstTerminal/sentinel
BIN=/usr/local/bin/sentinel
CONF_DIR=/etc/sentinel
DATA_DIR=/var/lib/sentinel
UNIT=/etc/systemd/system/sentinel.service

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "this installer is for Linux; on other systems use Docker or a release binary"
[ "$(id -u)" = 0 ] || die "run it as root: curl -fsSL ... | sudo sh"
command -v systemctl >/dev/null 2>&1 || die "systemd is needed (or run the Docker image instead)"
command -v curl >/dev/null 2>&1 || die "curl is needed"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is needed"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "no release binary for $(uname -m); build from source (see README)" ;;
esac

VERSION=${SENTINEL_VERSION:-}
if [ -z "$VERSION" ]; then
  # The latest release's page redirects to .../tag/vX.Y.Z.
  VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/tag/v||')
  case "$VERSION" in [0-9]*.[0-9]*.[0-9]*) ;; *) die "could not find the latest release" ;; esac
fi
VERSION=${VERSION#v}
FILE="sentinel-$VERSION-linux-$ARCH"
BASE="https://github.com/$REPO/releases/download/v$VERSION"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
say "Downloading Sentinel $VERSION for linux/$ARCH"
curl -fsSL -o "$TMP/$FILE" "$BASE/$FILE" || die "download failed: $BASE/$FILE"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt" || die "download failed: checksums.txt"

say "Checking the checksum"
(cd "$TMP" && grep " $FILE\$" checksums.txt | sha256sum -c -) >/dev/null || die "checksum mismatch: the download is damaged or was changed"
if command -v cosign >/dev/null 2>&1; then
  say "Checking the signature (cosign)"
  curl -fsSL -o "$TMP/checksums.txt.sigstore.json" "$BASE/checksums.txt.sigstore.json" || die "download failed: signature"
  cosign verify-blob --bundle "$TMP/checksums.txt.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$REPO/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$TMP/checksums.txt" >/dev/null 2>&1 || die "signature check failed"
else
  echo "    (install cosign to also check the release signature)"
fi

UPDATE=false
[ -x "$BIN" ] && UPDATE=true
install -m 0755 "$TMP/$FILE" "$BIN"

if ! id sentinel >/dev/null 2>&1; then
  say "Creating the sentinel system user"
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin sentinel 2>/dev/null ||
    useradd -r -d "$DATA_DIR" -s /sbin/nologin sentinel
fi
mkdir -p "$CONF_DIR" "$DATA_DIR"
chown sentinel: "$DATA_DIR"
chmod 0700 "$DATA_DIR"

if [ ! -f "$CONF_DIR/sentinel.yaml" ]; then
  say "Writing $CONF_DIR/sentinel.yaml"
  "$BIN" init "$CONF_DIR/sentinel.yaml" >/dev/null
  if [ -n "${UPSTREAM:-}" ]; then
    case "$UPSTREAM" in http://* | https://*) ;; *) die "UPSTREAM must start with http:// or https://" ;; esac
    sed -i "s|^upstream: .*|upstream: $UPSTREAM|" "$CONF_DIR/sentinel.yaml"
  fi
fi
"$BIN" check-config "$CONF_DIR/sentinel.yaml" || die "fix $CONF_DIR/sentinel.yaml, then run: systemctl restart sentinel"

say "Installing the systemd service"
cat >"$UNIT" <<'EOF'
[Unit]
Description=Sentinel security gateway
After=network-online.target
Wants=network-online.target

[Service]
User=sentinel
ExecStart=/usr/local/bin/sentinel -config /etc/sentinel/sentinel.yaml
ExecReload=/bin/kill -HUP $MAINPID
Environment=DATA_DIR=/var/lib/sentinel
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/sentinel
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
if $UPDATE; then
  systemctl restart sentinel
  say "Sentinel updated to $VERSION and restarted"
else
  systemctl enable --now sentinel
  say "Sentinel $VERSION is running"
fi

LISTEN=$(sed -n 's/^listen: *"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$CONF_DIR/sentinel.yaml" | head -n1)
PORT=${LISTEN##*:}
cat <<EOF

  Config:  $CONF_DIR/sentinel.yaml   (then: systemctl restart sentinel)
  Data:    $DATA_DIR
  Logs:    journalctl -u sentinel -f

EOF
if ! $UPDATE; then
  sleep 2
  LINK=$(journalctl -u sentinel --no-pager -o cat 2>/dev/null | grep -o 'http[^ "]*/__sentinel/setup#[^ "]*' | tail -n1 || true)
  if [ -n "$LINK" ]; then
    echo "  Create the admin account: $LINK"
  else
    echo "  Create the admin account: journalctl -u sentinel | grep 'FIRST RUN'"
  fi
  echo "  Dashboard: http://<this server>:${PORT:-8080}/__sentinel/dashboard"
fi
