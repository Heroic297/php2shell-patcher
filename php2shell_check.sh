#!/usr/bin/env bash
# php2shell_check.sh - READ-ONLY PHP2Shell (CVE-2026-109618 / CVE-2026-109619) scanner.
# Makes no changes, no network requests, no exploit tests. Prints no secrets.
# Usage: php2shell_check.sh [--json] [--no-docker] [--records] [--label NAME]
# Exit: 0 all PATCHED, 1 any VULNERABLE/UNSUPPORTED, 2 only UNKNOWN/none found.
set -u
LC_ALL=C; export LC_ALL
VERSION="1.1.0"
FIXED_82=35; FIXED_83=36; FIXED_84=27; FIXED_85=12
CVE_A="109618"; CVE_B="109619"
JSON=0; DOCKER=1; RECORDS=0; LABEL="host:$(hostname 2>/dev/null || echo unknown)"
INI_KEYS="memory_limit post_max_size upload_max_filesize session.upload_progress.enabled fatal_error_backtraces"

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --no-docker) DOCKER=0 ;;
    --records) RECORDS=1 ;;           # internal: machine records (used by verify / docker recursion)
    --label) shift; LABEL="${1:-$LABEL}" ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac; shift
done

# ---------- helpers ----------
have() { command -v "$1" >/dev/null 2>&1; }
log() { [ "$JSON" = 1 ] || [ "$RECORDS" = 1 ] || printf '%s\n' "$*"; }
json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }

# verdict_for_version X.Y.Z -> PATCHED|VULNERABLE|UNSUPPORTED|UNKNOWN
verdict_for_version() {
  local v="$1" maj min pat fixed
  case "$v" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo UNKNOWN; return ;; esac
  maj=${v%%.*}; min=${v#*.}; min=${min%%.*}; pat=${v#*.*.}; pat=${pat%%[!0-9]*}
  [ -z "$pat" ] && { echo UNKNOWN; return; }
  if [ "$maj" -lt 8 ] || { [ "$maj" = 8 ] && [ "$min" -le 1 ]; }; then echo UNSUPPORTED; return; fi
  [ "$maj" = 8 ] || { echo UNKNOWN; return; }
  case "$min" in 2) fixed=$FIXED_82;; 3) fixed=$FIXED_83;; 4) fixed=$FIXED_84;; 5) fixed=$FIXED_85;; *) echo UNKNOWN; return;; esac
  if [ "$pat" -ge "$fixed" ]; then echo PATCHED; else echo VULNERABLE; fi
}

php_version_of() { # binary -> X.Y.Z (php -v output; never executes user scripts)
  local v
  v=$("$1" -n -v 2>/dev/null | sed -n '1s/^PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
  # lsphp rejects -n (prints usage); plain -v only prints the version banner
  [ -z "$v" ] && v=$("$1" -v 2>/dev/null </dev/null | sed -n '1s/^PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
  printf '%s' "$v"
}

# Package owning a file + whether its changelog mentions both CVE ids (distro backport).
pkg_of() {
  local f="$1" p=""
  if have dpkg-query; then
    p=$(dpkg-query -S "$f" 2>/dev/null | head -1 | cut -d: -f1)
    [ -n "$p" ] && { printf 'deb:%s=%s' "$p" "$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null)"; return; }
  fi
  if have rpm; then
    p=$(rpm -qf "$f" 2>/dev/null | head -1)
    case "$p" in *"not owned"*|"") ;; *) printf 'rpm:%s' "$p"; return;; esac
  fi
  printf 'none'
}
changelog_has_fix() { # pkgref -> yes|no|unknown
  local ref="$1" name text=""
  case "$ref" in
    deb:*) name=${ref#deb:}; name=${name%%=*}
      local src d
      src=$(dpkg-query -W -f='${source:Package}' "$name" 2>/dev/null)
      for d in "/usr/share/doc/$name" "/usr/share/doc/${src:-x}" "/usr/share/doc/${name%-*}-common"; do
        for f in "$d/changelog.Debian.gz" "$d/changelog.gz"; do
          [ -r "$f" ] && text="$text$(zcat "$f" 2>/dev/null | head -400)"
        done
        [ -r "$d/changelog.Debian" ] && text="$text$(head -400 "$d/changelog.Debian")"
      done ;;
    rpm:*) name=${ref#rpm:}; text=$(rpm -q --changelog "$name" 2>/dev/null | head -400) ;;
    *) echo unknown; return ;;
  esac
  [ -z "$text" ] && { echo unknown; return; }
  if printf '%s' "$text" | grep -q "$CVE_A" && printf '%s' "$text" | grep -q "$CVE_B"; then echo yes; else echo no; fi
}

ini_of_bin() { # binary -> "k=v;k=v" from the binary's own ini (CLI/FPM php.ini + conf.d)
  local b="$1" out="" k v
  case "$(basename "$b")" in
    php-fpm*|php-cgi*|lsphp*) # these SAPIs can't run -r; use -i (prints config only)
      local info; info=$("$b" -i 2>/dev/null | sed -e 's/<[^>]*>/ /g' -e 's/&quot;//g')   # php-cgi -i prints HTML
      for k in $INI_KEYS; do
        v=$(printf '%s\n' "$info" | awk -v k="$k" '$1==k { print ($2=="=>" ? $3 : $2); exit }')
        out="$out$k=${v:-n/a};"
      done ;;
    frankenphp) # embedded PHP reads the same php.ini / conf.d as the server
      for k in $INI_KEYS; do
        v=$("$b" php-cli -r "\$x=ini_get('$k'); echo \$x===false?'n/a':\$x;" 2>/dev/null | head -1)
        out="$out$k=${v:-n/a};"
      done ;;
    *)
      for k in $INI_KEYS; do
        v=$("$b" -r "\$x=ini_get('$k'); echo \$x===false?'n/a':\$x;" 2>/dev/null | head -1)
        out="$out$k=${v:-n/a};"
      done ;;
  esac
  out=$(printf '%s' "$out" | tr -d '|\n\r')
  case "$out" in *Usage:*|*sage:*) out="";; esac
  printf '%s' "$out"
}

fpm_pool_overrides() { # all pool files -> "file|key|value" lines for our keys
  local f
  for f in /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf /etc/php-fpm.d/*.conf /opt/remi/*/root/etc/php-fpm.d/*.conf /etc/opt/remi/*/php-fpm.d/*.conf; do
    [ -r "$f" ] || continue
    sed -n 's/^[[:space:]]*php_\(admin_\)\{0,1\}\(value\|flag\)\[\([^]]*\)\][[:space:]]*=[[:space:]]*\([^;[:space:]]*\).*/\3|\4/p' "$f" |
      while IFS='|' read -r k v; do
        case " $INI_KEYS " in *" $k "*) printf '%s|%s|%s\n' "$f" "$k" "$v";; esac
      done
  done
}

proc_list() { # "pid comm args" for processes in OUR pid namespace (reads /proc; works without ps)
  local self d pid comm args
  self=$(readlink /proc/self/ns/pid 2>/dev/null)
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    if [ -n "$self" ]; then [ "$(readlink "$d/ns/pid" 2>/dev/null)" = "$self" ] || continue; fi
    comm=$(cat "$d/comm" 2>/dev/null) || continue
    args=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
    printf '%s %s %s\n' "$pid" "$comm" "$args"
  done
}

detect_sapis() {
  local ps; ps=$(proc_list); local s=""
  printf '%s\n' "$ps" | grep -q 'php-fpm' && s="$s fpm(running)"
  printf '%s\n' "$ps" | grep -Eq '(^| )(lsphp|litespeed|lshttpd|openlitespeed)' && s="$s litespeed(running)"
  printf '%s\n' "$ps" | grep -q 'frankenphp' && s="$s frankenphp(running)"
  printf '%s\n' "$ps" | grep -q 'php-cgi' && s="$s cgi(running)"
  if printf '%s\n' "$ps" | grep -Eq '(apache2|httpd)'; then
    if ls /etc/apache2/mods-enabled/php*.load /etc/httpd/conf.modules.d/*php*.conf >/dev/null 2>&1 ||
       { have apachectl && apachectl -M 2>/dev/null | grep -q php; }; then s="$s apache-mod_php(running)"; else s="$s apache(no mod_php)"; fi
  elif ls /etc/apache2/mods-enabled/php*.load /etc/httpd/conf.modules.d/*php*.conf >/dev/null 2>&1; then
    s="$s apache-mod_php(enabled,not running)"
  fi
  have frankenphp && case "$s" in *frankenphp*) ;; *) s="$s frankenphp(installed)";; esac
  [ -z "$s" ] && s=" none-detected"
  printf '%s' "${s# }"
}

find_binaries() {
  local d f seen=" "
  for d in $(printf '%s' "$PATH" | tr ':' ' ') /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib/cgi-bin /opt/*/bin /opt/*/root/usr/bin /opt/*/root/usr/sbin /opt/remi/*/root/usr/bin /opt/remi/*/root/usr/sbin /opt/cpanel/ea-php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/sbin /usr/local/lsws/lsphp*/bin; do
    [ -d "$d" ] || continue
    for f in "$d"/php "$d"/php[0-9]* "$d"/php-fpm* "$d"/php-cgi* "$d"/lsphp* "$d"/frankenphp; do
      { [ -x "$f" ] && [ -f "$f" ]; } || continue
      case "$f" in *-config*|*ize*|*dbg*) continue;; esac
      local r; r=$(readlink -f "$f" 2>/dev/null || echo "$f")
      case "$seen" in *" $r "*) continue;; esac
      seen="$seen$r "; printf '%s\n' "$r"
    done
  done
}

# ---------- scan ----------
CSAPIS=""
RECS=""   # lines: source|binary|version|sapi_kind|pkg|backport|verdict|ini
add_rec() { RECS="$RECS$1"$'\n'; }

scan_local() {
  local b v pkg bp verdict kind ini
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    case "$(basename "$b")" in php-fpm*) kind=fpm;; php-cgi*) kind=cgi;; lsphp*) kind=litespeed;; frankenphp) kind=frankenphp;; *) kind=cli;; esac
    if [ "$kind" = cli ]; then   # trust the binary's own SAPI tag, e.g. /usr/lib/cgi-bin/php8.2 is cgi
      case "$("$b" -n -v 2>/dev/null | head -1)" in *"(cgi-fcgi)"*) kind=cgi;; *"(fpm-fcgi)"*) kind=fpm;; *"(litespeed)"*) kind=litespeed;; esac
    fi
    if [ "$kind" = frankenphp ]; then v=$("$b" version 2>/dev/null | sed -n 's/.*PHP \([0-9.]*\).*/\1/p' | head -1); else v=$(php_version_of "$b"); fi
    pkg=$(pkg_of "$b"); bp=$(changelog_has_fix "$pkg")
    verdict=$(verdict_for_version "${v:-x}")
    if [ "$bp" = yes ] && [ "$verdict" != PATCHED ]; then verdict="PATCHED"; bp="yes(backport)"; fi
    ini=$(ini_of_bin "$b" "$kind")
    add_rec "$LABEL|$b|${v:-?}|$kind|$pkg|$bp|$verdict|$ini"
  done <<EOT
$(find_binaries)
EOT
  # mod_php shared object (no binary to run): version from the package
  local so
  for so in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/local/lib/apache2/modules/libphp*.so; do
    [ -f "$so" ] || continue
    pkg=$(pkg_of "$so"); bp=$(changelog_has_fix "$pkg")
    v=$(printf '%s' "$pkg" | sed -n 's/.*=\([0-9]*:\)\{0,1\}\([0-9]*\.[0-9]*\.[0-9]*\).*/\2/p')
    [ -z "$v" ] && v=$(grep -aoE '[78]\.[0-9]\.[0-9]{1,2}' "$so" 2>/dev/null | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
    verdict=$(verdict_for_version "${v:-x}"); [ "$bp" = yes ] && [ "$verdict" != PATCHED ] && { verdict=PATCHED; bp="yes(backport)"; }
    add_rec "$LABEL|$so|${v:-?}|apache-mod_php|$pkg|$bp|$verdict|"
  done
}

scan_docker() {
  [ "$DOCKER" = 1 ] && have docker || return 0
  docker ps -q >/dev/null 2>&1 || { log "  (docker present but not accessible; run with docker permission to scan containers)"; return 0; }
  local id name out
  for id in $(docker ps -q); do
    name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    if docker exec "$id" sh -c 'command -v bash' >/dev/null 2>&1; then
      out=$(docker exec -i "$id" bash -s -- --records --no-docker --label "container:$name" < "$0" 2>/dev/null)
    else
      local v; v=$(docker exec "$id" sh -c 'php -v 2>/dev/null || php-fpm -v 2>/dev/null' | sed -n '1s/^PHP \([0-9.]*\).*/\1/p')
      out=""; [ -n "$v" ] && out="container:$name|php|$v|unknown|none|unknown|$(verdict_for_version "$v")|"
    fi
    [ -n "$out" ] && RECS="$RECS$(printf '%s\n' "$out" | grep -v '^#')"$'\n'
    CSAPIS="$CSAPIS$(printf '%s\n' "$out" | sed -n 's/^#sapis|\([^|]*\)|\(.*\)/\1: \2/p')"$'\n'
    POOLS="$POOLS$(printf '%s\n' "$out" | sed -n "s/^#pool|/container:$name:/p")"$'\n'
  done
}

SAPIS=$(detect_sapis)
POOLS=$(fpm_pool_overrides)
scan_local
scan_docker
RECS=$(printf '%s' "$RECS" | sed '/^$/d'); CSAPIS=$(printf '%s' "$CSAPIS" | sed '/^$/d'); POOLS=$(printf '%s' "$POOLS" | sed '/^$/d')

if [ "$RECORDS" = 1 ]; then
  printf '#sapis|%s|%s\n' "$LABEL" "$SAPIS"
  printf '%s\n' "$POOLS" | sed '/^$/d; s/^/#pool|/'
  [ -n "$RECS" ] && printf '%s\n' "$RECS"
  exit 0
fi

# Docker sub-records include their own #sapis/#pool lines (filtered above), recompute counts
worst=0; n=0
while IFS='|' read -r src bin ver kind pkg bp verdict ini; do
  [ -n "${src:-}" ] || continue; n=$((n+1))
  case "$verdict" in VULNERABLE|UNSUPPORTED) worst=1;; UNKNOWN) [ $worst = 0 ] && worst=2;; esac
done <<EOT
$RECS
EOT
[ "$n" = 0 ] && worst=2

if [ "$JSON" = 1 ]; then
  printf '{"tool":"php2shell_check","version":"%s","cves":["CVE-2026-109618","CVE-2026-109619"],' "$VERSION"
  printf '"fixed":{"8.2":"8.2.35","8.3":"8.3.36","8.4":"8.4.27","8.5":"8.5.12"},'
  printf '"host":"%s","scanned_at":"%s","sapis":"%s","container_sapis":"%s","installs":[' "$(json_esc "$LABEL")" "$(date -Iseconds)" "$(json_esc "$SAPIS")" "$(json_esc "$(printf '%s' "$CSAPIS" | tr '\n' ';')")"
  first=1
  while IFS='|' read -r src bin ver kind pkg bp verdict ini; do
    [ -n "${src:-}" ] || continue
    [ $first = 1 ] || printf ','; first=0
    printf '{"source":"%s","binary":"%s","version":"%s","sapi":"%s","package":"%s","changelog_fix":"%s","verdict":"%s","ini":{' \
      "$(json_esc "$src")" "$(json_esc "$bin")" "$(json_esc "$ver")" "$kind" "$(json_esc "$pkg")" "$bp" "$verdict"
    f2=1; IFS=';' read -ra kvs <<<"$ini"
    for kv in "${kvs[@]}"; do [ -n "$kv" ] || continue; [ $f2 = 1 ] || printf ','; f2=0; printf '"%s":"%s"' "$(json_esc "${kv%%=*}")" "$(json_esc "${kv#*=}")"; done
    printf '}}'
  done <<EOT
$RECS
EOT
  printf '],"fpm_pool_overrides":['
  first=1
  while IFS='|' read -r f k v; do
    [ -n "${f:-}" ] || continue; [ $first = 1 ] || printf ','; first=0
    printf '{"file":"%s","key":"%s","value":"%s"}' "$(json_esc "$f")" "$(json_esc "$k")" "$(json_esc "$v")"
  done <<EOT
$POOLS
EOT
  case $worst in 0) o=PATCHED;; 1) o=ACTION_REQUIRED;; *) o=UNKNOWN;; esac
  printf '],"overall":"%s"}\n' "$o"
  exit $worst
fi

echo "PHP2Shell check v$VERSION  (CVE-2026-109618 / CVE-2026-109619)  read-only"
echo "Fixed: 8.2.35  8.3.36  8.4.27  8.5.12   (8.1 and older: unsupported)"
echo "Target: $LABEL    SAPIs: $SAPIS"
[ -n "$CSAPIS" ] && printf '%s\n' "$CSAPIS" | sed 's/^/  SAPIs in /'
echo
if [ "$n" = 0 ]; then echo "No PHP installs found."; fi
while IFS='|' read -r src bin ver kind pkg bp verdict ini; do
  [ -n "${src:-}" ] || continue
  printf '[%-11s] %s  %s  (%s)\n' "$verdict" "$src" "$bin" "$ver"
  printf '              sapi=%s package=%s changelog_fix=%s\n' "$kind" "$pkg" "$bp"
  [ -n "$ini" ] && printf '              %s\n' "$(printf '%s' "$ini" | tr ';' ' ')"
done <<EOT
$RECS
EOT
if [ -n "$POOLS" ]; then echo; echo "FPM pool overrides (php_value/php_admin_value):"; printf '%s\n' "$POOLS" | sed 's/^/  /'; fi
echo
case $worst in
  0) echo "Overall: all detected installs PATCHED. Confirm workers were restarted (php2shell_verify.sh).";;
  1) echo "Overall: ACTION REQUIRED. Update to a fixed release or your distro's backport and restart every worker. 8.1 and older: take offline or use a vendor LTS backport. Temporary mitigations: php2shell_mitigate.sh (dry-run by default).";;
  *) if [ "$n" = 0 ]; then echo "Overall: no PHP found on this target (bundled PHP in vendor products may still exist)."; else echo "Overall: UNKNOWN. Some installs could not be classified; check them manually."; fi;;
esac
echo "Also check vendor products bundling PHP: https://github.com/NCSC-NL/php2shell"
exit $worst
