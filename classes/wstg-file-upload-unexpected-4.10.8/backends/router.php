<?php
// PolyRange BUSL-08 backend — php -S router. Upload accepts only "images".
//
// T0: validates the client-supplied Content-Type header only — trivially
// spoofed (image/png) on a .php upload.
// T1: additionally sniffs the first bytes of the request body for an image
// magic. The Content-Type spoof alone no longer suffices; the body itself
// must begin with a real image-format magic. The bypass is a polyglot whose
// first bytes are a valid GIF magic (GIF89a/GIF87a) followed by PHP code —
// once written under /uploads/, php -S still executes the .php body, which
// is the whole point of the RCE.
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$docroot = $_SERVER['DOCUMENT_ROOT'] ?: __DIR__;
$dir = $docroot . '/uploads';
if (!is_dir($dir)) @mkdir($dir, 0777, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $uri === '/upload') {
    // WEAK: trusts the client-supplied Content-Type header.
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';
    if (!preg_match('#^image/(png|jpe?g|gif|webp)#i', $ct)) {
        http_response_code(415);
        echo 'Only image uploads are allowed.';
        return true;
    }
    $body = file_get_contents('php://input');

    // T1: magic-byte sniff. The runtime sets PR_DEFENCE_TIER=1 when the
    // deploy is T1. The first bytes of the request body MUST match a real
    // image format. A bare PHP payload fails; a polyglot beginning with a
    // GIF89a / GIF87a header passes.
    if ((int)(getenv('PR_DEFENCE_TIER') ?: 0) >= 1) {
        if (!is_image_magic($body)) {
            http_response_code(415);
            echo 'Uploaded content is not a recognised image format.';
            return true;
        }
    }

    $name = basename($_GET['name'] ?? '');
    if ($name === '') { http_response_code(400); echo 'name required'; return true; }
    file_put_contents("$dir/$name", $body);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Uploaded to /uploads/$name";
    return true;
}
return false; // php -S serves/executes docroot files (incl uploaded /uploads/*.php)

function is_image_magic($buf) {
    if (!is_string($buf) || strlen($buf) < 4) return false;
    $head8 = substr($buf, 0, 8);
    // GIF87a / GIF89a
    if (substr($head8, 0, 6) === 'GIF87a' || substr($head8, 0, 6) === 'GIF89a') return true;
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (substr($head8, 0, 8) === "\x89PNG\r\n\x1a\n") return true;
    // JPEG: FF D8 FF
    if (substr($buf, 0, 3) === "\xff\xd8\xff") return true;
    return false;
}
