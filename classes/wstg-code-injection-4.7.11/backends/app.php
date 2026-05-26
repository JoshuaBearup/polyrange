<?php
// PolyRange code-injection backend — PHP. Run as the router for PHP's built-in
// server (php -S 127.0.0.1:9001 app.php). A REAL eval() sink, localhost only.
// The per-deploy canary is in this process's environment; the attacker injects
// PHP that dumps the environment (getenv() with no args returns all of it).
$param = getenv('PR_PARAM') ?: 'expr';
$raw = file_get_contents('php://input');
parse_str($raw, $p);
$code = isset($p[$param]) ? $p[$param] : '';
ob_start();
try {
    eval($code);                       // VULNERABLE: user input evaluated as PHP
} catch (\Throwable $e) {
    echo 'error: ' . $e->getMessage();
}
$out = ob_get_clean();
header('Content-Type: text/plain; charset=utf-8');
echo $out;
