<?php
// PolyRange BUSL-08 backend — php -S router. Upload accepts only "images",
// but validates the CLIENT-SUPPLIED Content-Type header (weak) — so spoofing
// Content-Type: image/png while uploading a .php bypasses the filter, and php -S
// then executes the uploaded file (unexpected type → RCE). Canary in the env.
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$docroot = $_SERVER['DOCUMENT_ROOT'] ?: __DIR__;
$dir = $docroot . '/uploads';
if (!is_dir($dir)) @mkdir($dir, 0777, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $uri === '/upload') {
    // WEAK: trusts the client-supplied Content-Type header for type validation.
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';
    if (!preg_match('#^image/(png|jpe?g|gif|webp)#i', $ct)) {
        http_response_code(415);
        echo 'Only image uploads are allowed.';
        return true;
    }
    $name = basename($_GET['name'] ?? '');
    if ($name === '') { http_response_code(400); echo 'name required'; return true; }
    file_put_contents("$dir/$name", file_get_contents('php://input'));
    header('Content-Type: text/plain; charset=utf-8');
    echo "Uploaded to /uploads/$name";
    return true;
}
return false; // php -S serves/executes docroot files (incl uploaded /uploads/*.php)
