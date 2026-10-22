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
