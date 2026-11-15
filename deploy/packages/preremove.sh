#!/bin/sh
# Before removing the package: stop the service. Config and data are kept.
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop sentinel >/dev/null 2>&1 || true
  systemctl disable sentinel >/dev/null 2>&1 || true
fi
