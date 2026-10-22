# PHP2Shell Patcher (Grok Bot template core)

> **Disclaimer:** Unofficial community tool, not affiliated with or endorsed by the PHP project, CISA, or NSA. Test on a staging server before production; the authoritative fix is upgrading PHP. Sources: [php.net releases](https://www.php.net/archive/2026.php), [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching), [NSA Cybersecurity on X](https://x.com/nsacyber/status/2113068811058622971), [NCSC-NL php2shell](https://github.com/NCSC-NL/php2shell). Licensed MIT, provided as is.

Scripts for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell", unauthenticated RCE in PHP core).
Fixed releases: **8.5.12, 8.4.27, 8.3.36, 8.2.35**. 8.1 and older: unsupported (vendor LTS backport or take offline).
Distro packages may be patched by **backport** while `php -v` still shows an old version (the "php -v trap").

| Script | Writes? | Purpose |
|---|---|---|
| `php2shell_check.sh` | never | Inventory + verdict per install (PATCHED / VULNERABLE / UNSUPPORTED / UNKNOWN), `--json` |
| `php2shell_mitigate.sh` | only with `--apply` | php.net temporary mitigations, timestamped backups, `--rollback` |
| `php2shell_verify.sh` | never | Post-patch: versions, workers restarted, effective settings (FPM, LiteSpeed, FrankenPHP) |

## Usage
```bash
sudo ./php2shell_check.sh            # human report (sudo lets it inspect docker containers)
sudo ./php2shell_check.sh --json     # machine summary; exit 0 patched, 1 action required, 2 unknown/none
./php2shell_check.sh --no-docker     # skip containers

sudo ./php2shell_mitigate.sh                     # DRY-RUN: unified diff, nothing written
sudo ./php2shell_mitigate.sh --apply             # write (backs up to /var/backups/php2shell/<timestamp>/)
sudo ./php2shell_mitigate.sh --apply --restart   # also gracefully reload PHP workers
     --post-max 32M        # if the site needs uploads (php.net); upload_max_filesize is set 1M below
     --memory-unlimited    # memory_limit=-1 via php_admin_value; ONLY with a cgroup/container memory cap
sudo ./php2shell_mitigate.sh --rollback [TIMESTAMP] [--restart]
sudo ./php2shell_mitigate.sh --restart-only       # after a package upgrade: restart workers only, no config change

sudo ./php2shell_verify.sh [--json]   # exit 0 PASS, 1 FAIL, 2 inconclusive
```

### What check looks at
- Binaries: `php`, `php8.x`, `php-fpm*`, `php-cgi*`, `lsphp*`, `frankenphp` in PATH, `/usr/{s,}bin`, `/usr/local/{s,}bin`, `/opt/*` (cPanel EA, remi, LiteSpeed); Apache `libphp*.so`.
- SAPIs in use from `/proc` (works in minimal containers without `ps`; ignores other PID namespaces): fpm, apache mod_php (`mods-enabled/php*.load`, `conf.modules.d`), cgi, LiteSpeed, FrankenPHP.
- Package owner via `dpkg-query -S` / `rpm -qf` and the package changelog (`/usr/share/doc/*/changelog.Debian.gz`, `rpm -q --changelog`) for both CVE numbers (matches `CVE-2026-109618_109619.patch` style too). Both found → PATCHED (backport).
- Docker: each running container is scanned by piping this script into `docker exec -i <c> bash -s` (read-only; falls back to `php -v` if no bash).
- Settings: `memory_limit`, `post_max_size`, `upload_max_filesize`, `session.upload_progress.enabled`, `fatal_error_backtraces` for CLI (`ini_get`) and FPM (`php-fpm -i`), plus pool `php_value`/`php_admin_value` overrides.

### What mitigate changes (php.net temporary mitigations, NOT a fix)
- Drop-in `zz-php2shell-mitigation.ini` in each conf.d (fpm/apache2/cgi/cli/litespeed, `/usr/local/etc/php/conf.d`, `/etc/php.d`): `session.upload_progress.enabled=0`, `post_max_size`, `upload_max_filesize`, and `fatal_error_backtraces=0` on 8.5.
- Each FPM pool: a marked `php_admin_*` block appended to every pool section (cannot be overridden by apps). Re-runs are idempotent.
- After `--apply` it runs `php-fpm -t`; if the config is invalid it rolls itself back.
- Restart: prints `systemctl restart <unit>` (systemd: php*-fpm, php-fpm, remi `php8x-php-fpm`, ea-php, apache2/httpd, lsws/lshttpd, frankenphp) or, without systemd, `kill -USR2 <fpm master>` / `apachectl -k graceful` / `lswsctrl restart` plus stopping detached `lsphp` workers; runs them only with `--restart` or `--restart-only`.
- Works without `diff`/`cmp` (minimal RHEL/Rocky images): falls back to listing the added lines.

### Support matrix (tested in v1.1.0, see tests/RESULTS.md)
| Platform / SAPI | check | mitigate | restart | verify |
|---|---|---|---|---|
| Debian/Ubuntu php*-fpm (apt, backports) | yes | yes | systemd or USR2 | yes |
| RHEL/Rocky/Alma AppStream php-fpm (dnf module) | yes | yes (`/etc/php.d`, `/etc/php-fpm.d`) | systemd or USR2 | yes |
| Remi SCL `php8x-php-fpm` | paths covered | paths covered | systemd unit matched | paths covered (not run end to end, see limits) |
| Official `php:*-fpm` / `-apache` images | yes | yes | USR2 / graceful | yes |
| OpenLiteSpeed + lsphp | yes (`lsphp -v`) | yes (lsphp `mods-available` scan dir) | `lswsctrl restart` + stop detached lsphp | yes |
| FrankenPHP | yes (`frankenphp version`, `php-cli` ini) | yes (`/usr/local/etc/php/conf.d`) | **not automatic**: restart the frankenphp service/container yourself | yes (flags a process older than the change) |
| LiteSpeed Enterprise / CloudLinux alt-php / cPanel EA | paths covered | paths covered | systemd | untested |

### What verify proves
- Every install PATCHED (version or changelog backport).
- No PHP master runs a deleted (replaced-on-disk) binary, and the master or its newest worker generation started after the newest PHP binary/package/config change (2 s slack for /proc tick rounding).
- Effective FPM values = FPM ini merged with pool `php_admin_*` as parsed by `php-fpm -tt`; LiteSpeed (`lsphp -i`) and FrankenPHP (`frankenphp php-cli`) values from their php.ini/conf.d.
- LiteSpeed with no lsphp alive counts as OK (lsphp starts on demand with the current binary).

## Safety model
1. **Read-only by default.** check and verify never write; mitigate is a dry-run unless `--apply`.
2. **Every change needs the user's approval.** The bot shows the dry-run diff and restart commands on an approval card per host; nothing is applied, restarted, upgraded, or taken offline without a yes. Package upgrades (`apt-get install --only-upgrade php8.x-*`, `dnf upgrade php*`, new image tag) are proposed, never run silently.
3. **Backups before every write**, manifest + `--rollback`.
4. **Never exploit-test.** No PoCs, no crafted requests, no network probes, especially not against production.
5. **No secrets.** Only the five ini values above are read; no env, no config secrets, no credentials are printed.
6. **Shared hosting** (no root/SSH): the bot drafts a message for the user to send to their host, e.g. *"Please confirm my account's PHP version is patched for CVE-2026-109618/109619 (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or a distro backport), that PHP workers were restarted, and whether session.upload_progress is disabled until then."* The user sends it.
7. Vendor appliances bundling PHP: check https://github.com/NCSC-NL/php2shell; don't modify them, follow the vendor.

## Tests
See `tests/RESULTS.md` and `tests/logs/`.
