# PHP2Shell research (gathered 2026-10-21, ~9:10 PM ET)

## CVEs
- CVE-2026-109618: RCE via OOM corruption (GHSA-w8hw-w9fx-j79w). CVSS v4 9.2 (php.net CNA), vector AV:N/AC:H/AT:P/PR:N/UI:N.
- CVE-2026-109619: RCE via stale global state reused by a later request on the same worker (GHSA-6wmf-4rv5-p3rp). CVSS v4 9.2.
- Nickname: "PHP2Shell". Unauthenticated RCE in PHP core, not in apps. WordPress/Laravel updates do not fix it.

## Affected / fixed
- Fixed: 8.5.12, 8.4.27, 8.3.36, 8.2.35 (released 2026-10-21, ~13:40 UTC per ENISA).
- Affected: 8.2.x <8.2.35, 8.3.x <8.3.36, 8.4.x <8.4.27, 8.5.x <8.5.12 (NVD). 8.1 and older affected and EOL; php.net posted minimal source backports for 7.4, 8.0, 8.1. Distros/LTS vendors got patches in advance (check distro package, note backports mean `php -v` may show old version string).
- At risk: every PHP install serving web requests: PHP-FPM, Apache mod_php (highest risk, demonstrated pre-app-code exploit), php-cgi, FrankenPHP, LiteSpeed.
- remirepo had no updates on 10/21; php.net says switch to distro packages or build from source.
- PHP embedded in appliances/vendor products: see NCSC-NL list.

## Exploitation status
- CISA (10/21): has NOT observed exploitation as of publication.
- NSA: actors "likely to weaponize". Not in CISA KEV (checked feed version 2026.10.21, 1754 entries, no match).
- An X post (daniel_petrica) claims details were made public before the patch; unverified.

## Official remediation
1. Inventory every PHP install, incl. bundled in other software. Prioritize internet-facing.
2. Update to fixed version or vendor backport. Restart all workers.
3. Can't patch / 8.1 or older: take offline (CISA, NSA, NCSC). WAF may help partially (CISA); Cloudflare says it deployed WAF rules (X claim, not verified on Cloudflare's site).
4. Temporary mitigations (php.net, explicitly NOT complete):
   - 109618: memory_limit=-1 via php_admin_value (not overridable); post_max_size=8M (32M if uploads); upload_max_filesize < post_max_size; server/proxy limits on body size, field/part/header counts; cgroup/container memory limit; do NOT use RLIMIT_AS/RLIMIT_DATA.
   - 109619: session.upload_progress.enabled=0 in php.ini/pool config (not ini_set or .user.ini), restart every worker. On 8.5: fatal_error_backtraces=0. Remove invalid per-request settings that emit diagnostics; fix attacker-reachable fatal errors/timeouts.
5. Detection (CISA): monitor for PHP worker processes spawning shells or downloading tools; add enhanced logging (NSA).

## Demand signals on X
- NSA update post: 18.4k views, 420 likes, 112 RT, 76 bookmarks in ~25 min. NSA original warning: 7.96M views, 55.5k likes, 13.3k bookmarks, 947 replies.
- FBI Cyber post: 1.78M views, 6k bookmarks. Laravel pre-patch notice: 160k views.
- People asking/sharing how to patch: Ubuntu users waiting on ondrej PPA (RynoDarts180), WordPress host checklist article (mihai_respira, "php -v trap"), "ask an agent to check" (Dodgebert), user's ChatGPT agent monitoring for patch (DarwinSantosNYC), hosts posting status (SpaceshipStatus), vendors posting "not affected".

## Bot design (safe)
- Read-only first: SSH/local inventory (`php -v`, `php -i | grep -E 'Server API|memory_limit|session.upload_progress'`, `dpkg -l | grep php` / `rpm -qa | grep php`, container images, `docker exec ... php -v`), map distro package to vendor advisory for backports.
- Exposure: which SAPI, internet-facing or not, EOL versions, check NCSC-NL list for bundled products.
- Plan, then approval card per host before any upgrade, config change, or restart. Snapshot/backup config first. Never take systems offline without approval.
- Verify: version or vendor package fixed, workers restarted (process start times), mitigation settings effective in the running SAPI (phpinfo via FPM, not CLI), site health check.
- Monitor: process tree alerts (php-fpm -> sh/curl/wget), watch php.net/CISA KEV for exploitation changes.
- Draft host-provider ticket for shared hosting users (user sends).
- Never print credentials; no exploit testing against production.

## Sources read
- https://x.com/NSACyber/status/2113068811058622971 (quotes https://x.com/NSACyber/status/2112903220209098897)
- https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/nsa-advisory-critical-patches-recommended-for-php-vulnerabilities/
- https://www.php.net/archive/2026.php (advisory #2026-10-21-5 and release notes)
- https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-109618
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- https://www.enisa.europa.eu/news/joint-statement-on-critical-php-vulnerabilities
- https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php
- https://digital.nhs.uk/cyber-alerts/2026/cc-4875
- https://github.com/NCSC-NL/php2shell
