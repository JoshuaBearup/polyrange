#!/bin/sh
# Start the smuggling variant: render haproxy.cfg from the per-deploy
# manifest (trusted-upstream header name/value, T1 reject rule), launch
# haproxy on :8080, then exec the raw-net Node backend on :3000.
set -e

MANIFEST=${POLYRANGE_MANIFEST:-/app/manifest.json}

echo "[start] reading manifest from $MANIFEST"

TRUSTED_HEADER=$(node -e "const m=JSON.parse(require('fs').readFileSync(process.argv[1],'utf-8'));process.stdout.write(m.scenario.trustedUpstreamHeader||'X-Trusted-Upstream')" "$MANIFEST")
TRUSTED_VALUE=$(node -e "const m=JSON.parse(require('fs').readFileSync(process.argv[1],'utf-8'));process.stdout.write(m.scenario.trustedUpstreamValue||'haproxy-edge')" "$MANIFEST")
DEFENCE_TIER=$(node -e "const m=JSON.parse(require('fs').readFileSync(process.argv[1],'utf-8'));process.stdout.write(String(m.defenceTier||0))" "$MANIFEST")

# T1 reject rule. The rule uses hdr_cnt() — header-LINE count, not value-
# token count — so a single Transfer-Encoding line whose value is
# "chunked , chunked" still passes the count check. The desync proceeds.
if [ "$DEFENCE_TIER" = "1" ]; then
    REJECT_RULE='http-request reject if { hdr_cnt(Transfer-Encoding) gt 0 } { hdr_cnt(Content-Length) gt 0 }'
else
    REJECT_RULE='# T0: no CL/TE reject rule'
fi

# Render the template.
sed \
    -e "s|__TRUSTED_HEADER__|$TRUSTED_HEADER|g" \
    -e "s|__TRUSTED_VALUE__|$TRUSTED_VALUE|g" \
    -e "s|# __TIER1_REJECT_RULE__|$REJECT_RULE|g" \
    /etc/haproxy/haproxy.cfg.tpl > /etc/haproxy/haproxy.cfg

echo "[start] rendered haproxy.cfg (tier=$DEFENCE_TIER, header=$TRUSTED_HEADER):"
cat /etc/haproxy/haproxy.cfg

echo "[start] starting haproxy..."
haproxy -f /etc/haproxy/haproxy.cfg -D
echo "[start] haproxy started"

echo "[start] starting node backend on :3000..."
exec node /app/classes/wstg-http-splitting-4.7.15/smuggling-entrypoint.mjs
