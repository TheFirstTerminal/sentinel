#!/bin/sh
# After installing the package: a system user, a config file if there is
# none, and the service enabled. The service is started once upstream is set.
set -e
if ! id sentinel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/sentinel --shell /usr/sbin/nologin sentinel 2>/dev/null ||
    useradd -r -d /var/lib/sentinel -s /sbin/nologin sentinel
fi
chown sentinel: /var/lib/sentinel
chmod 0700 /var/lib/sentinel
[ -f /etc/sentinel/sentinel.yaml ] || /usr/bin/sentinel init /etc/sentinel/sentinel.yaml >/dev/null
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable sentinel >/dev/null 2>&1 || true
  if systemctl is-active --quiet sentinel; then systemctl restart sentinel || true; fi
fi
echo "Sentinel installed. Set upstream: in /etc/sentinel/sentinel.yaml, then: sudo systemctl start sentinel"
