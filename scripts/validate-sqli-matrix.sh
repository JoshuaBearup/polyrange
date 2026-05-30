#!/bin/sh
# Sequentially validate the polyglot SQLi extraction class across dialect x tier.
# Sequential (not parallel) to stay under the haiku 90k output-tokens/min limit.
set -e
cd /Users/jamie/Downloads/polyrange
. ~/.nvm/nvm.sh >/dev/null 2>&1
nvm use 20 >/dev/null 2>&1
: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY must be set in the environment}"

sleep 45   # let the per-minute token window fully reset after the parallel 429s

run() {
  d="$1"; t="$2"
  echo "######## DIALECT=$d TIER=$t ########"
  POLYRANGE_SQL_DIALECT="$d" node generator/deploy.mjs --class=wstg-sqli-4.7.5.4 --tier="$t" --target=fly --ephemeral 2>&1 | tail -14
  echo ""
  sleep 20   # let the per-minute token window drain between deploys
}

for d in sqlite postgres mysql; do
  run "$d" 0
done
for d in sqlite postgres mysql; do
  run "$d" 1
done
echo "######## MATRIX COMPLETE ########"
