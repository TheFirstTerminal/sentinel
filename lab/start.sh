#!/usr/bin/env bash
# Start the whole lab and open the demo menu, in one step.
#
#   bash lab/start.sh          (or double-click "Start Sentinel.bat" on Windows)
#
# Checks Docker, starts Docker Desktop if it is closed, builds and starts
# every container, waits until Sentinel answers, then opens the demo menu.

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")/.." || exit 1

# The First Terminal brand colours (256-colour): palm green, soft red, saffron for titles.
GREEN=$'\e[1;38;5;72m'; RED=$'\e[1;38;5;203m'; CYAN=$'\e[1;38;5;179m'; DIM=$'\e[2m'; RESET=$'\e[0m'
step() { printf "\n%s\n" "${CYAN}▶ $1${RESET}"; }
fail() {
  printf "\n%s\n" "${RED}✗ $1${RESET}"
  [ -n "$2" ] && printf "  %s\n" "$2"
  printf "  Still stuck? Open an issue with a screenshot of this window: https://github.com/TheFirstTerminal/sentinel/issues\n\n"
  read -r -p "  Press Enter to close." _
  exit 1
}

# wait_for SECONDS COMMAND...  (prints a dot every 2 seconds)
wait_for() {
  local limit=$1; shift
  local waited=0
  until "$@" >/dev/null 2>&1; do
    [ "$waited" -ge "$limit" ] && { echo; return 1; }
    printf "."; sleep 2; waited=$((waited + 2))
  done
  echo
}

printf "%s\n" "${CYAN}======================================================${RESET}"
printf "%s\n" "${CYAN}   SENTINEL  ·  starting the lab${RESET}"
printf "%s\n" "${CYAN}======================================================${RESET}"

# 1. Docker installed?
step "Checking Docker"
command -v docker >/dev/null 2>&1 ||
  fail "Docker is not installed." "Install Docker Desktop (step 1 of the lab guide), then try again."

# 2. Docker running? If not, try to open Docker Desktop and wait for it.
if ! docker info >/dev/null 2>&1; then
  # Installed for all users, or for this user only (the installer's other
  # choice, common on lab and university PCs).
  DD=""
  for c in "/c/Program Files/Docker/Docker/Docker Desktop.exe" \
           "${LOCALAPPDATA:+$(cygpath -u "$LOCALAPPDATA" 2>/dev/null)/Programs/DockerDesktop/Docker Desktop.exe}" \
           "/Applications/Docker.app"; do
    [ -n "$c" ] && [ -e "$c" ] && { DD=$c; break; }
  done
  if [ -n "$DD" ]; then
    printf "  Docker Desktop is closed, opening it (up to 3 minutes)"
    case $DD in
      *.app) open -a "$DD" ;;
      *) "$DD" >/dev/null 2>&1 & ;;
    esac
    wait_for 180 docker info ||
      fail "Docker Desktop did not start." "Open it yourself, wait until it says \"Engine running\", then try again."
  else
    fail "Docker is not running." "Open Docker Desktop, wait until it says \"Engine running\", then try again."
  fi
fi
printf "  %s\n" "${GREEN}✓ Docker is running${RESET}"

# 3. Build and start everything.
# No --build: the images are built once (first run) and then reused, and
# running containers are left as they are. lab/update.sh rebuilds after an update.
step "Starting the lab ${DIM}(the first time builds it, several minutes)${RESET}"
mkdir -p logs
# Linux: the gateway runs as a non-root user and must be able to write here.
[ "$(uname -s)" = "Linux" ] && chmod 777 logs 2>/dev/null
docker compose up -d ||
  fail "The lab did not start." "Scroll up for the red error message."

# 4. Wait until Sentinel and the apps answer.
step "Waiting for the apps to be ready"
# No "curl -o /dev/null" here: with path conversion switched off (top of this
# file), Windows curl can't open /dev/null and fails even when the app answered.
gateway_up() { curl -s --max-time 3 http://localhost:8080/ >/dev/null; }
juice_up()   { curl -s --max-time 3 http://localhost:3000/ >/dev/null; }
printf "  Sentinel  "; wait_for 120 gateway_up || fail "Sentinel did not answer on localhost:8080." "Run:  docker compose logs gateway"
printf "  Juice Shop"; wait_for 180 juice_up   || fail "Juice Shop did not answer on localhost:3000." "Run:  docker compose logs juice-shop"
printf "  %s\n" "${GREEN}✓ Everything is up${RESET}"

# 5. Old Sentinel still running after an update? (start.sh doesn't rebuild,
# so after getting new code the lab could keep running the previous build.)
# Compare the running version with the code's, and rebuild if they differ.
want=$(sed -n 's/^var Version = "\(.*\)"/\1/p' gateway/cmd/sentinel/main.go)
have=$(curl -s --max-time 3 http://localhost:8080/__sentinel/health | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
if [ -n "$want" ] && [ "$have" != "$want" ]; then
  step "Updating Sentinel ${DIM}(running: ${have:-an old version}, code: $want; a few minutes)${RESET}"
  docker compose up -d --build gateway || fail "Sentinel could not be rebuilt." "Scroll up for the red error message."
  printf "  Sentinel  "; wait_for 120 gateway_up || fail "Sentinel did not answer on localhost:8080." "Run:  docker compose logs gateway"
  printf "  %s\n" "${GREEN}✓ Sentinel $want is running${RESET}"
fi

sleep 1
exec bash lab/demo.sh
