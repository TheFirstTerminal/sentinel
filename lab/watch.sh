#!/usr/bin/env bash
# Sentinel live window: one coloured line per request, showing what
# Sentinel decided and why. The demo menu opens this automatically.
#
#   bash lab/watch.sh          decisions only
#   bash lab/watch.sh --all    also static files (noisy)
#
# Ctrl+C to stop.

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")/.." || exit 1
exec docker compose exec -T gateway /sentinel watch --color "$@" /logs/sentinel.log
