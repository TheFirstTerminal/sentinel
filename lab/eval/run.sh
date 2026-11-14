#!/usr/bin/env bash
# Runs inside the evaluation container (see lab/evaluate.sh).
DIRECT=${DIRECT:-http://juice-shop:3000}
GATEWAY=${GATEWAY:-http://gateway:8080}
OUT=/out/evaluation.md
URLPATH="/rest/products/search?q=apple"

echo "1/2  Replaying attacks and normal traffic..."
evaluate -direct "$DIRECT" -gateway "$GATEWAY" -n "${N:-1000}" -out "$OUT" >/dev/null || exit 1

echo "2/2  Running sqlmap (a real SQL injection tool), this takes a few minutes..."
sqlmap_run() {   # name url [extra args...]
  local name=$1 url=$2; shift 2
  local log=/tmp/sqlmap-$name.log
  timeout 600 sqlmap -u "$url" -p q --batch --random-agent --flush-session \
    --level=2 --risk=1 --technique=BEUT --time-sec=2 --timeout=10 --retries=1 --threads=4 \
    --disable-coloring --output-dir=/tmp/sq-$name "$@" >"$log" 2>&1
  local found="no" requests waf=""
  grep -q "identified the following injection point" "$log" && found="**yes**"
  grep -q "heuristics detected that the target is protected" "$log" && waf=" (sqlmap noticed a WAF/IPS)"
  requests=$(grep -o "[0-9]* HTTP(s) requests" "$log" | tail -1)
  printf "| %s | %s%s | %s |\n" "$name" "$found" "$waf" "${requests:-–}" >>"$OUT"
}
{
  echo
  echo "## 3. sqlmap"
  echo
  echo "sqlmap looks for SQL injection in the shop's search (\`$URLPATH\`). \"Found\" means it confirmed the database can be attacked."
  echo
  echo "| Target | Found an injection | Requests |"
  echo "|---|---|---|"
} >>"$OUT"
sqlmap_run "direct (no protection)" "$DIRECT$URLPATH"
sqlmap_run "through Sentinel" "$GATEWAY$URLPATH"
sqlmap_run "through Sentinel, with evasion (tamper scripts)" "$GATEWAY$URLPATH" --tamper=space2comment,randomcase,between,charencode
echo >>"$OUT"
echo "Done."
