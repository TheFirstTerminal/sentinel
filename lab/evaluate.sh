#!/usr/bin/env bash
# Measure how well Sentinel protects the lab, like an attacker would:
# replay thousands of attacks and normal requests, measure the time
# Sentinel adds, and run sqlmap (a real attack tool) with and without
# Sentinel. Takes about 10 minutes. The lab must be running.
#
#   bash lab/evaluate.sh
#
# Result: eval-results/evaluation.md

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")/.." || exit 1
mkdir -p eval-results
[ "$(uname -s)" = "Linux" ] && chmod 777 eval-results 2>/dev/null
echo "Building the evaluation tools (first time: a few minutes)..."
docker compose --profile eval build eval >/dev/null || { echo "Build failed. Scroll up for the error, or open an issue: https://github.com/tsxmamii/sentinel/issues"; exit 1; }
docker compose --profile eval run --rm eval || { echo "The evaluation failed. Is the lab running (bash lab/start.sh)?"; exit 1; }
echo
echo "Report: eval-results/evaluation.md"
echo "Afterwards choose R in the demo menu to reset the lab."
