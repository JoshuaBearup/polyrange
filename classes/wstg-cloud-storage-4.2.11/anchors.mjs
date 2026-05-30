// Per-deploy anchor for cloud-storage exposure (4.2.11) — fixes the exposure
// style of the open bucket/listing carrying the canary.
//
// Each entry names a real public-bucket/listing convention that attackers
// probe — different cloud providers have different listing-XML/JSON shapes,
// different self-hosted object stores have their own conventions, and old
// Apache/nginx misconfigurations still leak via directory indexes.

import crypto from 'node:crypto'

export const STYLE_POOL = [
  // ── Major cloud providers ──
  'an open S3-style bucket listing (XML ListBucketResult) enumerating objects, one of which holds the canary',
  'a GCS-style bucket JSON listing exposing object names + a sensitive object',
  'a public Azure-style blob/container index listing items including a leaked one',
  'an Aliyun OSS XML listing (ListBucketResult dialect with Owner / StorageClass extensions) enumerating objects',
  'an IBM Cloud Object Storage public listing (S3-API-compatible) enumerating objects',

  // ── S3-compatible storage (third-party) ──
  'a DigitalOcean Spaces public listing (S3-XML-compatible) exposing object keys',
  'a Cloudflare R2 public listing (S3-XML-compatible) exposing object keys',
  'a Wasabi public bucket listing (S3-XML-compatible) exposing object keys',
  'a Backblaze B2 native listing (b2_list_file_names JSON response) enumerating files',
  'a MinIO self-hosted S3-compatible listing exposing internal object keys',

  // ── Self-hosted / open-protocol object stores ──
  'an OpenStack Swift container listing (text/plain or JSON, one object per line)',
  'a Ceph Object Gateway (RGW) public listing exposing object names',
  'a Seaweed FS or MinIO browser HTML listing exposing object names',
  'a public WebDAV PROPFIND XML listing enumerating files in a directory',

  // ── Web-server directory indexes ──
  'an Apache/nginx-style open directory index (/uploads/, /files/) listing files including a sensitive one',
  'an IIS-style directory browsing index (no default doc) listing files including a sensitive one',
  'a Lighttpd mod_dirlisting HTML index enumerating files in a directory',
  'a Caddy file_server browse index listing files in a public directory',

  // ── Embedded asset / CDN manifests ──
  'an exposed CDN/asset manifest (a JSON index of uploaded files) referencing a private object',
  'a public bucket with an index.html landing page that lists or links to private object paths',
  'a sitemap-style JSON manifest of CDN assets referencing a private object',
  'a JSONL public listing (one JSON object per line, each describing a file) referencing a private object',
]

export function pickAnchor() {
  return 'The exposure is ' + STYLE_POOL[crypto.randomBytes(1)[0] % STYLE_POOL.length] +
    '. The listing endpoint enumerates several objects (realistic filenames); the canary is inside the CONTENT of the one sensitive object (served at its listed path), not in the listing itself. Represent that object as text (a config, an export, a note) with pr_<canary> as a natural value. The other listed objects are mundane decoys.'
}
