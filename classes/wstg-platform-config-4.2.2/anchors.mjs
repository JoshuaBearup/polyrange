// Per-deploy anchor for platform-config exposure (4.2.2) — fixes WHICH
// conventionally-exposed platform artifact carries the canary, so deploys
// spread across the real set of "files that should never be web-reachable".

import crypto from 'node:crypto'

export const ARTIFACT_POOL = [
  // ── .env family ──
  'a leaked /.env file with environment variables (DB creds, API keys, secrets)',
  'an exposed /.env.staging or /.env.prod environment-variant secret file',
  'an exposed /.env.local or /.env.development developer-env file',
  'an exposed /.env.backup or /.env.old backup of an env file',
  'an exposed /.env.txt (extension-stripped) developer copy of an env file',
  'an exposed /.env.example or /.env.sample template that was left with real values',
  'an exposed /.env.production.local (Next.js) with prod secrets',
  'an exposed /.env.development.local (Next.js) with dev secrets',
  'an exposed /api/.env env file under the api directory',
  'an exposed /admin/.env env file under the admin directory',
  'an exposed /config/.env env file under the config directory',
  'an exposed /backend/.env env file under the backend directory',

  // ── Git artefacts ──
  'an exposed /.git/config (and the implied repo) revealing remotes and internals',
  'a reachable /.git/HEAD or /.git/index exposing repository structure',
  'a reachable /.git/logs/HEAD revealing commit history with author info',
  'a reachable /.git/COMMIT_EDITMSG with last commit message and metadata',
  'a reachable /.gitignore revealing internal paths and secrets that were excluded',
  'an exposed /.git-credentials with cached repo credentials',

  // ── PHP diagnostic dumps ──
  'a /phpinfo.php dump exposing the full PHP environment',
  'an exposed /info.php or /test.php phpinfo-style dump',
  'an exposed /php_info.php or /i.php phpinfo-style dump',
  'an exposed /debug.php developer debug page with env dump',

  // ── .NET / IIS ──
  'an exposed /web.config (.NET) with connection strings / appSettings',
  'an exposed /web.config.bak (.NET) backup of web.config with old credentials',
  'an exposed /web.config.old or /web.config.orig with older credentials',
  'an exposed /appsettings.json (.NET Core) with secrets',
  'an exposed /appsettings.Production.json or /appsettings.Development.json with environment secrets',
  'an exposed /connectionStrings.config (.NET) with DB connection strings',
  'an exposed /Trace.axd (.NET) trace handler with request history',
  'an exposed /elmah.axd (.NET ELMAH) error log handler revealing internals',

  // ── Generic config files ──
  'a reachable /config.json or /config.yml with internal settings',
  'a reachable /settings.json or /configuration.json with internal settings',
  'a reachable /settings.yml or /settings.ini with internal settings',
  'a reachable /secrets.json with API keys and tokens',
  'a reachable /app.config or /application.config with environment settings',
  'a reachable /global.config with environment-wide settings',
  'an exposed /config.bak or /config.old backup config file',

  // ── Docker ──
  'an exposed /docker-compose.yml revealing services and env',
  'an exposed /docker-compose.prod.yml or /docker-compose.override.yml with prod settings',
  'an exposed /docker-compose.dev.yml or /docker-compose.staging.yml with env-specific settings',
  'an exposed /Dockerfile + build args revealing internals',
  'an exposed /Dockerfile.prod or /Dockerfile.dev environment-specific build files',
  'an exposed /.dockerignore revealing excluded internal paths',

  // ── Package-manager credential / lock files ──
  'a leaked /.npmrc or /.pypirc with a registry auth token',
  'a leaked /package.json with private registry credentials in dependencies',
  'a leaked /package-lock.json revealing private registry URLs and integrity hashes',
  'a leaked /yarn.lock with private registry URLs',
  'an exposed /composer.json or /composer.lock (PHP) with internal package details',
  'an exposed /Gemfile or /Gemfile.lock (Ruby) revealing internal dependencies',
  'an exposed /requirements.txt or /Pipfile (Python) revealing internal dependencies',

  // ── Cloud credentials ──
  'an exposed /.aws/credentials or /.aws/config cloud credential file',
  'an exposed /.gcloud/credentials or /.gcp/credentials file',
  'an exposed /azure-credentials.json or /.azure/credentials file',
  'an exposed /gcp-key.json or /service-account.json GCP service account key',
  'an exposed /.kube/config kubeconfig with cluster admin credentials',

  // ── WordPress ──
  'a reachable /wp-config.php backup with DB credentials',
  'a reachable /wp-config-old.php or /wp-config.php.bak with credentials',
  'an exposed /wp-config.php.txt extension-stripped WordPress config',
  'an exposed /wp-config.php.dist template wp-config left with real values',
  // Note: /.wp-config.php.swp belongs to WSTG-CONF-04 (backup-files), not CONF-02 —
  // WSTG-CONF-02 page explicitly punts editor-backup/swap files to CONF-04.

  // ── Apache htaccess family ──
  'an exposed /.htaccess and/or /.htpasswd pair',
  'an exposed /.htdigest digest-auth credential file',

  // ── Server status / well-known / debug endpoints ──
  'a /server-info or /server-status debug dump for the platform',
  'a reachable /.well-known/security.txt revealing internal contact metadata',
  'a reachable /metrics Prometheus-style metrics endpoint exposing internals',
  'a reachable /health or /healthz health-check endpoint leaking internal state',
  'a reachable /debug or /debug/vars Go expvar handler leaking internals',
  'a reachable /__debug__/ Django debug endpoint exposing internals',

  // ── IDE / project files ──
  'a reachable /.vscode/ or /.idea/ project config leaking paths',
  'a reachable /.vscode/settings.json with project-specific settings',
  'a reachable /.idea/workspace.xml with developer environment paths',
  'an exposed /.project or /.classpath Eclipse project file',
  'an exposed /.sln (.NET solution) or /.csproj revealing project structure',

  // ── Rails ──
  'a reachable /secrets.yml or /database.yml Rails config with credentials',
  'an exposed /master.key Rails credentials decryption key',
  'an exposed /config/credentials.yml.enc Rails encrypted credentials file',

  // ── Spring / Java ──
  'an exposed /application.properties or /application.yml Spring config with credentials',
  'an exposed /application-prod.properties or /application-dev.properties env-specific config',
  'an exposed /bootstrap.yml or /bootstrap.properties Spring Cloud bootstrap config',
  'an exposed /pom.xml (Maven) revealing internal package dependencies',
  'an exposed /META-INF/MANIFEST.MF revealing Java app metadata',

  // ── Terraform / K8s / IaC ──
  'an exposed /terraform.tfvars or /terraform.tfstate with infrastructure secrets',
  'an exposed /terraform.tfstate.backup with previous infrastructure state',
  'an exposed /.terraform.lock.hcl revealing provider versions',
  'an exposed /kustomization.yaml or /kubernetes-secrets.yaml with cluster secrets',
  'an exposed /helm/values.yaml with chart values including credentials',
  'an exposed /serverless.yml (Serverless framework) with provider config',
  'an exposed /cdk.json (AWS CDK) with stack config',

  // ── CI/CD config ──
  'a leaked /.gitlab-ci.yml or /.github/workflows/ CI config with embedded tokens',
  'a leaked /.circleci/config.yml CircleCI config with embedded secrets',
  'a leaked /.travis.yml Travis CI config with embedded secrets',
  'a leaked /Jenkinsfile pipeline definition with embedded credentials',
  'a leaked /azure-pipelines.yml Azure DevOps pipeline with credentials',
  'a leaked /buildspec.yml AWS CodeBuild spec with credentials',
  'a leaked /cloudbuild.yaml GCP Cloud Build config with credentials',

  // ── Modern framework configs ──
  'an exposed /next.config.js (Next.js) with embedded secrets',
  'an exposed /nuxt.config.js (Nuxt) with embedded secrets',
  'an exposed /vercel.json or /netlify.toml deployment config with env vars',

  // Note: editor backup/swap conventions (.swp, ~, .save) are scoped to
  // WSTG-CONF-04 (backup-files), not here. The CONF-02 page explicitly
  // says "swap/backup files likely belong to WSTG-CONF-04". Kept this
  // boundary clean during the 2026-05 anchor audit.
]

export function pickAnchor() {
  return 'The canary lives in ' + ARTIFACT_POOL[crypto.randomBytes(1)[0] % ARTIFACT_POOL.length] +
    '. Include 2-4 OTHER conventionally-exposed platform artifacts as decoys (no canary).'
}
