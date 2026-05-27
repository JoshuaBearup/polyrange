#!/bin/sh
# Seed the maildir, start dovecot, then ALWAYS start node. If dovecot fails to
# come up, the runtime's in-process IMAP fallback keeps the class working — node
# must start regardless (no 503/restart-loop).
echo "[start] seeding maildir..."
node /app/seed-maildir.mjs || true
chown -R vmail:vmail /srv/mail 2>/dev/null || true
echo "[start] starting dovecot..."
dovecot || echo "[start] dovecot failed to start — runtime will use in-process IMAP fallback"
echo "[start] waiting for IMAP :143 (max ~25s)..."
node -e "const net=require('net');let n=0;(function t(){if(n++>80){console.log('[start] :143 not up — using fallback');process.exit(0)}const s=net.connect(143,'127.0.0.1');s.on('connect',()=>{console.log('[start] dovecot ready on :143');s.end();process.exit(0)});s.on('error',()=>setTimeout(t,300))})()"
exec node /app/runtime/server.mjs
