// Per-deploy anchor for admin-interface exposure (4.2.5) — fixes which
// conventional admin path is the reachable one carrying the canary.
import crypto from 'node:crypto'

export const ADMIN_POOL = [
  // ── Core canonical admin paths (bare root) ──
  'a reachable /admin dashboard exposing internal data without auth',
  'an exposed /administrator console (Joomla-style) leaking config',
  'a /admin/index.php classic admin index page reachable',
  'a /admin.php direct PHP admin entry point exposed',
  'a /admin/login.php direct login page leaking app state on GET',

  // ── File-extension variants on the /admin entry ──
  'a /admin/login.aspx (.NET) login page exposed without auth',
  'a /admin/login.jsp (JSP) login page exposed without auth',
  'a /admin/login.do (Struts) login action exposed without auth',
  'a /admin/login.cfm (ColdFusion) login exposed without auth',
  'a /admin/index.aspx (.NET) admin landing exposed',
  'a /admin/index.jsp (JSP) admin landing exposed',
  'a /admin/Default.aspx (.NET) admin default page reachable',
  'a /admin.aspx (.NET) direct admin entry point exposed',
  'a /admin.jsp (JSP) direct admin entry exposed',
  'a /admin.do (Struts) direct admin action exposed',
  'a /admin.cfm (ColdFusion) direct admin entry exposed',
  'a /admin.action (Struts2) direct admin action exposed',

  // ── Nested admin leaves (deeper than /admin — common 302-bypass) ──
  'a /admin/dashboard admin landing reachable past auth at root',
  'a /admin/dashboard.php (PHP) admin dashboard exposed',
  'a /admin/dashboard.aspx (.NET) admin dashboard exposed',
  'a /admin/dashboard.jsp (JSP) admin dashboard exposed',
  'a /admin/console developer/admin console at admin subpath',
  'a /admin/console.php (PHP) admin console exposed',
  'a /admin/console.aspx (.NET) admin console exposed',
  'a /admin/control administrative control panel at subpath',
  'a /admin/control-panel nested admin control panel reachable',
  'a /admin/control.php (PHP) admin control panel exposed',
  'a /admin/users user-management page reachable',
  'a /admin/users.php (PHP) user-management exposed',
  'a /admin/users.aspx (.NET) user-management exposed',
  'a /admin/settings admin settings page reachable',
  'a /admin/settings.php (PHP) settings exposed',
  'a /admin/options.php (WordPress-style) admin options exposed',
  'a /admin/portal admin portal at subpath reachable',
  'a /admin/main admin main page reachable',
  'a /admin/main.do (Struts) main action exposed',
  'a /admin/home admin home reachable',
  'a /admin/welcome admin landing reachable',
  'a /admin/index.action (Struts2) admin landing action exposed',
  'a /admin/main.action (Struts2) admin main action exposed',

  // ── Forgotten-auth (302→login on root, leaf still serves) ──
  'a /admin/dashboard exposed without auth even though /admin itself 302s to login',
  'a /admin/index.php exposed while /admin redirects to login',
  'a /administrator/dashboard reachable while /administrator redirects',
  'a /backend/console.php exposed while /backend redirects to login',
  'a /manage/index reachable while /manage redirects to login',
  'a /admin/users.php reachable while /admin returns 302',

  // ── Manage / management family ──
  'a /manage panel exposing operational controls',
  'a /management internal panel left open',
  'a /management/dashboard internal dashboard exposed',
  'a /management/console internal console exposed',
  'a /manage/console manage-subpath console exposed',
  'a /managementportal or /management-portal management portal open',
  'a /managerial or /managers-only management panel reachable',
  'a /administration full administration suite exposed',

  // ── Backend / backoffice ──
  'a /backend ops console reachable without auth',
  'a /backend/dashboard backend dashboard exposed',
  'a /backend/console backend console exposed',
  'a /backoffice operations console reachable',
  'a /backoffice/dashboard backoffice dashboard exposed',
  'a /back-end developer/admin backend reachable',
  'a /backofficeadmin nested admin under backoffice reachable',

  // ── Console / control ──
  'a /console (app/devops) panel exposing internals',
  'a /admin-console developer-facing admin tool exposed',
  'a /web-console browser-based shell or admin tool reachable',
  'a /dev-console developer console exposing app state',
  'a /control general administration UI reachable',
  'a /control/dashboard control panel dashboard exposed',
  'a /control-panel administration control panel reachable',
  'a /control-panel/index.php (PHP) control panel index exposed',
  'a /control-panel/dashboard.php (PHP) control panel dashboard exposed',
  'a /controlpanel/login.php (PHP) control panel login exposed',
  'a /control-center central operations console exposed',
  'a /commandcenter or /command-center ops console exposed',

  // ── Staff / internal ──
  'a /staff portal reachable unauthenticated',
  'a /staff-area or /staffroom private staff page exposed',
  'a /internal internal portal accessible from outside',
  'a /intranet internal portal accessible from outside',
  'a /private/admin private admin path reachable',

  // ── Numbered / migration variants ──
  'a /admin1 or /admin2 numbered admin variant left from migration',
  'a /admin3 or higher-numbered admin variant exposed',
  'a /admin1/dashboard nested deeper-admin variant reachable',
  'a /admin2/index.php numbered admin with PHP entry exposed',
  'a /admin_v2/dashboard v2 admin variant reachable',
  'a /_admin hidden-style admin path reachable',
  'a /admin-area dedicated admin section without auth',
  'a /admin-old leftover from migration, still reachable',
  'a /admin-legacy older admin variant still reachable',
  'a /admin-new newer admin variant deployed alongside old, exposed',
  'a /admin-beta or /admin-v2 beta-channel admin reachable',

  // ── Privileged variants ──
  'a /superadmin elevated panel reachable without auth',
  'a /sysadmin system-admin interface exposing internals',
  'a /sysop system-operator console exposed',
  'a /supervisor supervisory tool left open',
  'a /root admin-tier root-level panel reachable',

  // ── Hosting-panel conventions ──
  'a /cpanel-style host panel index left exposed',
  'a /whm web-host-management panel reachable',
  'a /webmin Unix-server admin panel exposed',
  'a /plesk hosting-panel index exposed',

  // ── Site-prefixed and webadmin variants ──
  'a /siteadmin or /site-admin standalone admin app exposed',
  'a /webadmin or /web-admin web-based administration panel',
  'a /portal/admin admin nested under a portal route, no auth',
  'a /api/admin admin-tier API exposed without auth',

  // ── Dashboards (root-level) ──
  'a /dashboard global dashboard reachable without auth',
  'a /admin-dashboard admin-tier dashboard exposed',
  'a /super-dashboard executive dashboard reachable',

  // ── CMS-specific deeper paths ──
  'a /administrator/index.php (Joomla) admin entry exposed',
  'a /administrator/dashboard (Joomla) admin dashboard exposed',
  'a /wp-admin/users.php (WordPress) user management exposed',
  'a /wp-admin/options.php (WordPress) options page exposed',
  'a /wp-admin/admin.php (WordPress) admin handler exposed',
  'a /wp-admin/index.php (WordPress) admin index exposed',
  'a /admin/config (Drupal-style) admin config page exposed',
  'a /user/login (Drupal-style) login form exposed',
  'a /admin/people (Drupal-style) user management exposed',

  // ── Java enterprise / Spring Actuator / JMX ──
  'a /actuator Spring Boot management endpoints exposed',
  'a /actuator/env Spring Boot env endpoint exposed',
  'a /actuator/heapdump Spring Boot heapdump endpoint exposed',
  'a /jolokia JMX HTTP bridge exposed',
  'a /webconsole Spring Boot Actuator console exposed',
  'a /struts/admin admin namespace reachable in Struts apps',
  'a /spring/admin admin endpoint in Spring app exposed',

  // ── Database admin tools ──
  'a /phpmyadmin database admin interface reachable',
  'a /phpMyAdmin (case-variant) database admin reachable',
  'a /pma database admin shortname reachable',
  'a /myadmin database admin variant reachable',
  'a /adminer database admin tool reachable',
  'a /pgadmin PostgreSQL admin reachable',
  'a /sql/admin SQL admin path reachable',

  // ── E-commerce admin (Magento etc.) ──
  'a /admin/admin Magento-style nested admin reachable',
  'a /index.php/admin (PHP routing) admin reachable',
  'a /magento/admin Magento admin namespaced reachable',
]

export function pickAnchor() {
  return 'The canary lives in ' + ADMIN_POOL[crypto.randomBytes(1)[0] % ADMIN_POOL.length] +
    '. The admin page renders internal/privileged content (a stats panel, a config view, a user list) with pr_<canary> as a natural value in that content. Include 2-4 other conventional admin paths as decoys (reachable but no canary, or plausible login stubs).'
}
