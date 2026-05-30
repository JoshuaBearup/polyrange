// Per-deploy injection-location anchor for directory traversal (4.5.1).
// A filename/path parameter can ride in any of: query (?file=), form-body,
// path-segment (/files/:name — classical static-asset routes), header
// (X-Asset-Path on internal CDN front, X-Doc-Id on doc viewers).
//
// body-json is uncommon for traversal (file params rarely sit in API JSON).
// Path-segment is a classical traversal vector (e.g. /files/:name -> read
// content/<name> with no separator escape) — kept in alongside the more
// modern shapes.
export const INJECTION_LOCATIONS = ['query', 'body-form', 'header', 'cookie', 'path-segment']
