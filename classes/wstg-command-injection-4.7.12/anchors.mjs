// Per-deploy injection-location anchor for command-injection (4.7.12).
// Real-world shell-injection feeds can come from any HTTP position — a search
// box that builds `ping ${host}`, a JSON API that fwds an arg to `git clone`,
// a per-tenant header rendered into an admin command, a path-segment lookup
// that triggers a backup script. Spread across these so a model that only
// probes ?host= catches a small fraction.
// path-segment is realistic for command injection — e.g. /ping/:host where
// host is concatenated into `ping <host>` directly.
export const INJECTION_LOCATIONS = ['query', 'body-form', 'body-json', 'header', 'cookie', 'path-segment']
