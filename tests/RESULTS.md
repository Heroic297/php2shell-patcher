# Test results (2026-10-21, ~9:45 PM ET, Docker 26.1.5 on the box)

Real Docker Hub images were available at both vulnerable and fixed versions, so no version-override fixture was needed.

| Target | Image | Expected | check verdict | mitigate dry/apply/rollback | verify |
|---|---|---|---|---|---|
| 8.3 vulnerable FPM | php:8.3.35-fpm | VULNERABLE | VULNERABLE | 4 files diffed / applied + USR2 / restored | FAIL (version) as expected; settings `[pool] ok` after apply, `EXPOSED` after rollback |
| 8.4 vulnerable FPM | php:8.4.26-fpm | VULNERABLE | VULNERABLE | pass | FAIL (version) as expected |
| 8.3 fixed FPM | php:8.3.36-fpm | PATCHED | PATCHED | n/a | PASS |
| 8.5 fixed FPM | php:8.5.12-fpm | PATCHED | PATCHED | pass, adds fatal_error_backtraces=0 (8.5 only) | PASS |
| 8.1 Apache mod_php | php:8.1-apache | UNSUPPORTED | UNSUPPORTED (CLI + libphp.so 8.1.34) | conf.d drop-in; mod_php/CLI shows upload_progress=0, post 8M, upload 7M; graceful reload | FAIL (unsupported) as expected |
| Ubuntu 24.04 distro pkg | php8.3-fpm 8.3.6-0ubuntu0.24.04.13 | PATCHED via backport (php -v trap) | PATCHED, changelog_fix=yes(backport) | pass (fpm+cli conf.d, pool.d) | PASS |
| Debian 12 distro pkg | php8.2-fpm 8.2.35-1~deb12u1 (+php-cgi) | PATCHED | PATCHED, changelog_fix=yes; cgi detected | pass | PASS |
| Rocky 9 (rpm path) | php-fpm 8.0.30-8.el9_8 | UNSUPPORTED | UNSUPPORTED, rpm changelog read (no CVE) | not run | not run |
| Box host | Debian 13 php8.4 8.4.27 | PATCHED | PATCHED | not applied on host | n/a |
| No PHP | debian:bookworm | none | "no PHP found", exit 2 | n/a | n/a |

Extra cases
- Stale worker (simulated apt upgrade: binary replaced on disk) -> verify FAIL "runs a DELETED binary"; after `kill -USR2 1` -> PASS (`30_stale_worker_ubuntu.txt`).
- Idempotence: dry-run after apply -> "Nothing to change" (`14_...`).
- Dry-run writes nothing: no /var/backups/php2shell, conf.d unchanged (`10_...`).
- JSON from check and verify parses (`02_check_all.json`, `50_verify_json_85.json`).
- Non-root without docker access: host-only scan, still valid JSON (`51_...`).
- shellcheck, all severities: clean (`00_shellcheck.txt`).

Bugs found and fixed during testing: libphp.so version misread as 2.9.14 (libxml); container processes counted as host SAPIs; official images lack `ps` (switched to /proc); FPM USR2 keeps master start time (now uses newest worker generation); 1 s /proc rounding (2 s slack); php-cgi `-i` prints HTML; `/usr/lib/cgi-bin/php8.2` misclassified as CLI and its usage text corrupted records.

---

# v1.1.0 extended tests (2026-10-21, ~9:40-10:10 PM ET)

| # | Target | Image / package | Expected | Result | Evidence |
|---|---|---|---|---|---|
| 1 | RPM path | rockylinux:9 + AppStream `php:8.2` module, php-fpm 8.2.33-1.module+el9.8.0 | VULNERABLE; mitigate + USR2; verify detects | PASS: check VULNERABLE (fpm, cli, cgi; rpm changelog read), dry-run writes nothing, apply 2 files (`/etc/php.d`, `/etc/php-fpm.d/www.conf`), `php -i` shows upload_progress Off / 8M / 7M, idempotent re-run, verify `[pool] ok` + workers restarted, rollback restores both files | `60_rocky9_rpm.txt` |
| 2a | systemd restart | jrei/systemd-ubuntu:24.04 (systemd PID 1, privileged, host cgroupns), php8.3-fpm 8.3.6-0maysync1 (no backport) | `--restart` uses systemctl | PASS: plan prints `systemctl restart php8.3-fpm.service`; MainPID 6231 -> 6573; verify OK on new master | `70_systemd_mitigate.txt` |
| 2b | stale binary after package upgrade | same, upgrade to 8.3.6-0ubuntu0.24.04.13 with restarts deferred (policy-rc.d 101) | verify FAILs until restart | PASS: check PATCHED (backport), verify `FAIL ... runs a DELETED binary` + fix hint; `--restart-only` -> systemctl restart, MainPID 20474 -> 27029, verify PASS; rollback --restart OK | `71_systemd_stale_upgrade.txt` |
| 3a | OpenLiteSpeed lsphp 8.5.12 | litespeedtech/openlitespeed:latest | PATCHED | PASS (after fix: lsphp version was `?`/UNKNOWN in v1.0.0) | `80_litespeed.txt` |
| 3b | OpenLiteSpeed lsphp 8.4.24 | :1.9.2-lsphp84 | VULNERABLE | PASS; mitigation drop-in in lsphp scan dir, `lswsctrl restart` + lsphp workers stopped, verify shows lsphp upload_progress Off | `80_litespeed.txt` |
| 3c | OpenLiteSpeed lsphp 8.1.33 | :1.8.4-lsphp81 | UNSUPPORTED | PASS | `80_litespeed.txt` |
| 3d | FrankenPHP 1.13.2 / PHP 8.5.12 | dunglas/frankenphp:latest | PATCHED | PASS; ini read via `frankenphp php-cli` | `81_frankenphp.txt` |
| 3e | FrankenPHP 1.12.7 / PHP 8.4.26 | dunglas/frankenphp:1.12-php8.4 | VULNERABLE | PASS; drop-in applied; restart is manual by design: verify FAILs "started BEFORE last PHP change" until `docker restart`, then OK | `81_frankenphp.txt` |
| 4a | New-owner run, own-server path | bot flow against php:8.3.35-fpm with files downloaded from the v1.1.0 tag | end to end | see `95_new_owner_own_server.txt` | `95_...` |
| R | Regression | php:8.3.35-fpm, 8.5.12-fpm, 8.1-apache, Ubuntu 24.04, Debian 12 | same as v1.0.0 | PASS, no change in verdicts | `90_regression_v110.txt` |

Note: FrankenPHP tags `1.13.1-php8.x` had already been rebuilt with fixed PHP (8.5.12 / 8.3.36), so 1.12.7 was used for the vulnerable case. Rocky AppStream had no fixed php 8.2 build yet (8.2.33 was latest), so the RPM upgrade step itself could not be exercised.

Bugs found and fixed in v1.1.0
1. Minimal RHEL/Rocky has no `diff`/`cmp` (diffutils): dry-run printed "command not found" and idempotence used a failing `cmp`. Now falls back to `cksum` compare and an added-lines listing.
2. verify listed `/usr/sbin/php-fpm` twice on RPM systems (glob + literal); FPM binaries are now de-duplicated (also in mitigate's `php-fpm -t` check).
3. Remi SCL (`/opt/remi/php8x/root/usr/{s,}bin`, `/etc/opt/remi/*/php.d`) binaries were not scanned and the `php8x-php-fpm.service` unit was not matched for restart.
4. `lsphp -n -v` prints usage, so LiteSpeed lsphp got version `?` and overall UNKNOWN. Falls back to `lsphp -v`.
5. No LiteSpeed restart command (non-systemd): now `lswsctrl restart` plus stopping detached lsphp workers.
6. FrankenPHP ini values were not read; now via `frankenphp php-cli`. FrankenPHP restart is reported as a manual step (never auto-run).
7. verify showed no effective settings for lsphp/FrankenPHP; added. LiteSpeed with no lsphp alive no longer gives an inconclusive result.
8. After a package upgrade there was no restart-only action, and "Nothing to change" hid the restart commands. Added `--restart-only`; verify prints the fix hint on stale workers.
