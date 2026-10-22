#!/usr/bin/env bash
# php2shell_verify.sh - READ-ONLY post-patch verification for PHP2Shell.
# Confirms: (1) versions are fixed or distro-backported (via php2shell_check.sh),
# (2) PHP worker processes started AFTER the PHP package/binary and config were last changed,
# (3) effective FPM settings = FPM php.ini/conf.d values overridden by pool php_admin_value.
# Usage: php2shell_verify.sh [--json]   Exit 0 = pass, 1 = fail, 2 = inconclusive
set -u
LC_ALL=C; export LC_ALL
HERE=$(cd "$(dirname "$0")" && pwd)
JSON=0; [ "${1:-}" = --json ] && JSON=1
fail=0; warn=0; out=""
say() { out="$out$1"$'\n'; }
CLK=$(getconf CLK_TCK 2>/dev/null || echo 100)
BOOT=$(awk '/^btime/{print $2}' /proc/stat)
pstart() { local st; st=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'); [ -n "$st" ] && echo $((BOOT + st / CLK)); }
fmt() { date -d "@$1" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo "$1"; }

# 1. versions
recs=$(bash "$HERE/php2shell_check.sh" --records --no-docker 2>/dev/null)
say "== Versions"
while IFS='|' read -r src bin ver _ pkg bp verdict _; do
  case "$src" in '#'*|'') continue;; esac
  say "  [$verdict] $bin $ver ($pkg${bp:+, changelog_fix=$bp})"
  case "$verdict" in PATCHED) ;; UNKNOWN) warn=1;; *) fail=1;; esac
done <<EOT
$recs
EOT

# 2. workers restarted after update / config change
say "== Worker restart"
newest_change() { # newest mtime among a PHP binary, its package list file, conf files
  local b="$1" t m f
  t=$(stat -c %Y "$b" 2>/dev/null || echo 0)
  for f in /var/lib/dpkg/info/php*.list /etc/php /usr/local/etc/php /usr/local/etc/php-fpm.d /etc/php.d /etc/php-fpm.d \
           /etc/php/*/fpm/conf.d/* /etc/php/*/fpm/pool.d/* /usr/local/etc/php/conf.d/* /usr/local/etc/php-fpm.d/* /etc/php.d/* /etc/php-fpm.d/*; do
    [ -e "$f" ] || continue; m=$(stat -c %Y "$f" 2>/dev/null || echo 0); [ "$m" -gt "$t" ] && t=$m
  done
  if have_rpm=$(command -v rpm) && [ -n "$have_rpm" ]; then
    m=$(rpm -qf --qf '%{INSTALLTIME}\n' "$b" 2>/dev/null | head -1); case "$m" in [0-9]*) [ "$m" -gt "$t" ] && t=$m;; esac
  fi
  echo "$t"
}
found=0
for d in /proc/[0-9]*; do
  pid=${d#/proc/}; comm=$(cat "$d/comm" 2>/dev/null) || continue
  case "$comm" in php-fpm*|apache2|httpd|lsphp|frankenphp|php-cgi*) ;; *) continue;; esac
  [ "$(readlink "$d/ns/pid" 2>/dev/null)" = "$(readlink /proc/self/ns/pid)" ] || continue
  exe=$(readlink "$d/exe" 2>/dev/null); exe=${exe% (deleted)}
  cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
  ppid=$(awk '{print $4}' "$d/stat" 2>/dev/null)
  # judge masters/parents only (workers of same exe inherit)
  pcomm=$(cat "/proc/$ppid/comm" 2>/dev/null); [ "$pcomm" = "$comm" ] && continue
  found=1; st=$(pstart "$pid"); ch=$(newest_change "${exe:-/nonexistent}")
  # graceful reloads (php-fpm USR2, apache graceful) keep the parent PID; the children are new.
  kids=$(for k in /proc/[0-9]*; do [ "$(awk '{print $4}' "$k/stat" 2>/dev/null)" = "$pid" ] && pstart "${k#/proc/}"; done | sort -n | head -1)
  [ -n "$kids" ] && [ "$kids" -gt "${st:-0}" ] && { cmd="${cmd}[workers since $(fmt "$kids")]"; st=$kids; }
  if readlink "$d/exe" 2>/dev/null | grep -q '(deleted)'; then
    say "  FAIL pid $pid $comm runs a DELETED binary (old version still in memory) -> restart it"; fail=1
  elif [ -n "$st" ] && [ $((st + 2)) -ge "$ch" ]; then   # 2s slack: /proc start times are tick-rounded
    say "  OK   pid $pid ($cmd) started $(fmt "$st") >= last PHP change $(fmt "$ch")"
  else
    say "  FAIL pid $pid ($cmd) started $(fmt "${st:-0}") BEFORE last PHP change $(fmt "$ch") -> restart it"; fail=1
  fi
done
[ "$found" = 0 ] && { say "  no running PHP worker processes found (nothing serving, or SAPI not detected)"; warn=1; }

# 3. effective FPM settings
say "== Effective FPM settings (php.ini/conf.d of FPM binary, overridden by pool php_admin_*)"
KEYS="memory_limit post_max_size upload_max_filesize session.upload_progress.enabled fatal_error_backtraces"
for b in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm /usr/sbin/php-fpm; do
  [ -x "$b" ] || continue
  ver=$("$b" -n -v 2>/dev/null | sed -n '1s/^PHP \([0-9]\.[0-9]\).*/\1/p')
  info=$("$b" -i 2>/dev/null)
  cfg=$("$b" -tt 2>&1 | sed -n 's/.*NOTICE:[[:space:]]*//p')   # parsed pool config, as FPM sees it
  for k in $KEYS; do
    base=$(printf '%s\n' "$info" | awk -v k="$k" '$1==k && $2=="=>" {print $3; exit}')
    pool=$(printf '%s\n' "$cfg" | sed -n "s/^php_admin_value\[$k\] = \(.*\)/\1/p" | tail -1)
    eff=${pool:-$base}; src=$([ -n "$pool" ] && echo pool || echo ini)
    [ -z "$eff" ] && continue
    st=info
    case "$k" in
      session.upload_progress.enabled) case "$eff" in 0|Off|off|"") st=ok;; *) st=EXPOSED;; esac ;;
      fatal_error_backtraces) [ "$ver" = 8.5 ] && case "$eff" in 0|Off|off|"") st=ok;; *) st=EXPOSED;; esac ;;
    esac
    say "  $b  $k = $eff  [$src] $st"
    [ "$st" = EXPOSED ] && warn=1
  done
done
say "  note: EXPOSED only matters if the install is not yet PATCHED (mitigations are temporary)."

if [ $fail = 1 ]; then res=FAIL; rc=1; elif [ $warn = 1 ]; then res=CHECK; rc=2; else res=PASS; rc=0; fi
# EXPOSED settings on a patched, restarted host are fine
if [ $fail = 0 ] && ! printf '%s' "$out" | grep -q 'no running\|\[UNKNOWN\]'; then res=PASS; rc=0; fi
if [ "$JSON" = 1 ]; then
  printf '{"tool":"php2shell_verify","result":"%s","details":"%s"}\n' "$res" "$(printf '%s' "$out" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s\\n",$0}')"
else
  printf '%s' "$out"; echo "RESULT: $res"
fi
exit $rc
