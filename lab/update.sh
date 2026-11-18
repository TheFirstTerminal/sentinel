#!/usr/bin/env bash
# Get the latest version of Sentinel from GitHub and restart the lab.
#
#   bash lab/update.sh
#

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")/.." || exit 1

GREEN=$'\e[1;32m'; RED=$'\e[1;31m'; RESET=$'\e[0m'

echo "Getting the latest version from GitHub..."
if ! git pull --ff-only; then
  echo
  echo "${RED}Could not update.${RESET} Usually a project file was changed by accident."
  echo "Run  git status  to see which files changed, or open an issue: https://github.com/TheFirstTerminal/sentinel/issues"
  exit 1
fi

echo
echo "Rebuilding and restarting the lab (a few minutes after a big update)..."
mkdir -p logs
[ "$(uname -s)" = "Linux" ] && chmod 777 logs 2>/dev/null
if ! docker compose up -d --build; then
  echo
  echo "${RED}The lab did not start.${RESET} Is Docker Desktop open and running?"
  exit 1
fi

echo
echo "${GREEN}Done. You have the latest version.${RESET}"
echo "What changed:  CHANGELOG.md"
echo "Opening the lab now. "
sleep 2
exec bash lab/start.sh
