// Per-deploy anchor for WEB APPLICATION (product / CMS / off-the-shelf)
// fingerprinting (4.1.9). The specific product is identifiable from a
// generator meta tag, a vendor header, a favicon, or its well-known admin /
// status / API endpoints — and that endpoint leaks the canary. We anchor each
// deploy to one product so deploys spread across the long tail. The LLM fills
// in the realistic version, headers/meta, and authentic endpoint output.

import crypto from 'node:crypto'

export const STACK_POOL = [
  // ── CMS / publishing ──
  'WordPress (X-Generator / <meta name=generator>, /wp-admin, /wp-login.php, /wp-json/wp/v2/users, /readme.html version)',
  'Drupal (X-Generator: Drupal, X-Drupal-Cache, /user/login, /CHANGELOG.txt, /core/CHANGELOG.txt, /update.php)',
  'Joomla (/administrator, /README.txt, /language/en-GB/en-GB.xml version, X-Content-Powered-By)',
  'TYPO3 (/typo3 backend, /typo3conf, generator meta)',
  'Concrete CMS (/dashboard, /index.php/dashboard, generator meta)',
  'Ghost (/ghost admin, /api/v3/content, X-Powered-By, generator meta)',
  'MediaWiki (/wiki/Special:Version, /api.php, generator meta)',
  'phpBB (/adm, style cookies, generator meta)',
  'Grav CMS (/admin, X-Powered-By: Grav)',
  'October CMS (/backend, default October artifacts)',
  'Sitecore (/sitecore, sitecore cookies)',
  'Umbraco (/umbraco, UMB-* cookies)',
  'DotNetNuke / DNN (/Install, /DesktopModules, DNN cookies)',
  'Adobe Experience Manager AEM (/crx/de, /system/console, /bin/querybuilder.json, /libs/granite)',

  // ── E-commerce ──
  'Magento (/downloader, /admin, /magento_version, Mage-* cookies)',
  'PrestaShop (/admin, PrestaShop-* cookies, generator meta)',
  'OpenCart (/admin, default OpenCart footer / version)',
  'Shopware (/admin, /api, sw-* artifacts)',

  // ── Dev / CI / repos ──
  'Jenkins (/script Groovy console, /manage, /systemInfo, /api/json, X-Jenkins header)',
  'GitLab (/-/health, /-/metrics, /help shows version, /api/v4/version)',
  'Gitea (/api/v1/version, default Gitea footer)',
  'SonarQube (/api/system/status, /api/server/version)',
  'Sonatype Nexus Repository (/service/rest/v1/status, /service/rest/v1/repositories)',
  'JFrog Artifactory (/artifactory/api/system/ping, /artifactory/api/system/version)',
  'TeamCity (/app/rest/server, RememberMe cookie)',
  'Drone CI (/healthz, /version)',
  'Argo CD (/api/version, /healthz)',
  'Concourse CI (/api/v1/info)',
  'Harbor registry (/api/v2.0/systeminfo, /api/v2.0/health)',

  // ── Observability / data UIs ──
  'Grafana (/api/health, /login, X-Grafana-* artifacts)',
  'Kibana (/api/status, /app/kibana)',
  'Prometheus (/-/healthy, /api/v1/status/buildinfo, /metrics)',
  'Alertmanager (/api/v2/status)',
  'Elasticsearch (/, /_cat/indices, /_cluster/health, /_nodes)',
  'OpenSearch (/, /_cluster/health, /_plugins)',
  'Apache Solr (/solr/admin/info/system, /solr/#/)',
  'Apache Superset (/health, /api/v1/me)',
  'Apache Airflow (/health, /api/v1/version, /admin)',
  'Metabase (/api/health, /api/session/properties)',
  'Redash (/ping, /api/session)',
  'Netdata (/api/v1/info)',
  'Zabbix (/api_jsonrpc.php, zbx_session cookie)',
  'Grafana Loki (/ready, /loki/api/v1/status/buildinfo)',

  // ── Data stores with HTTP UIs ──
  'CouchDB (/, /_utils Fauxton, /_all_dbs, /_membership)',
  'Neo4j (/db/data, /browser, neo4j auth realm)',
  'ArangoDB (/_admin/aardvark, /_api/version)',
  'ClickHouse (/, /play, /replicas_status)',
  'InfluxDB (/health, /ping, /debug/vars)',
  'MinIO (/minio/health/live, /minio/v2/metrics/cluster)',
  'phpMyAdmin (/phpmyadmin, /pma, version in footer)',
  'Adminer (/adminer.php, default Adminer login)',

  // ── Collaboration / ticketing ──
  'Atlassian Confluence (/status, /rest/api/space, X-Confluence-Request-Time)',
  'Atlassian Jira (/status, /rest/api/2/serverInfo, atlassian.xsrf.token)',
  'Redmine (/admin, default Redmine version footer)',
  'Discourse (/srv/status, /about.json, generator meta)',
  'Rocket.Chat (/api/info)',
  'Mattermost (/api/v4/system/ping, MMAUTHTOKEN)',
  'osTicket (/scp, default osTicket footer)',
  'Zammad (/api/v1/getting_started)',
  'Nextcloud (/status.php, /ocs/v2.php, nc_* cookies)',
  'Moodle (/admin, MoodleSession cookie, /lib/upgrade.txt version)',

  // ── Infra / admin panels ──
  'HashiCorp Consul (/v1/agent/self, /ui)',
  'HashiCorp Vault (/v1/sys/health, /v1/sys/seal-status)',
  'HashiCorp Nomad (/v1/agent/self)',
  'Portainer (/api/status, /api/system/info)',
  'Rancher (/ping, /v3, /v1)',
  'Kubernetes API server (/version, /healthz, /openapi/v2)',
  'Webmin (default :10000 panel, /session_login.cgi)',
  'Cockpit (default :9090 panel, /cockpit/login)',
  'Proxmox VE (/api2/json/version, PVEAuthCookie)',
  'Adobe ColdFusion (/CFIDE/administrator, /CFIDE/adminapi, CFID/CFTOKEN cookies)',
]

export function pickAnchor() {
  const i = crypto.randomBytes(2).readUInt16BE(0) % STACK_POOL.length
  return STACK_POOL[i]
}
