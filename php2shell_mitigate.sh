#!/usr/bin/env bash
# php2shell_mitigate.sh - official php.net TEMPORARY mitigations for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619). NOT a fix: update PHP and restart workers.
#
# Default is DRY-RUN: prints a unified diff of what would change, writes nothing.
#   --apply            write changes (backs up every touched file first)
#   --restart          after --apply/--rollback, gracefully reload PHP workers
#   --rollback [TS]    undo the latest (or given) backup set
#   --post-max SIZE    post_max_size cap (default 8M; php.net: 32M if you need uploads)
#   --memory-unlimited also set memory_limit=-1 via php_admin_value (php.net option;
#                      ONLY with a cgroup/container memory limit in place)
#   --backup-dir DIR   default /var/backups/php2shell
set -u
LC_ALL=C; export LC_ALL
MODE=dry; RESTART=0; POST_MAX=8M; MEMU=0; BK_ROOT=/var/backups/php2shell; RB_TS=""
MARK_B="; BEGIN php2shell-mitigation (CVE-2026-109618/109619) - remove after patching"
MARK_E="; END php2shell-mitigation"
DROPIN=zz-php2shell-mitigation.ini

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) MODE=apply ;;
    --restart) RESTART=1 ;;
    --rollback) MODE=rollback; case "${2:-}" in [0-9]*) RB_TS=$2; shift;; esac ;;
    --post-max) shift; POST_MAX=${1:?size}; ;;
    --memory-unlimited) MEMU=1 ;;
    --backup-dir) shift; BK_ROOT=${1:?dir} ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac; shift
done
case "$POST_MAX" in [0-9]*[MmKk]|[0-9]*) ;; *) echo "bad --post-max" >&2; exit 64;; esac
have() { command -v "$1" >/dev/null 2>&1; }

to_bytes() { local v=${1%[MmKkGg]} u=${1#"${1%[MmKkGg]}"}; case "$u" in [Kk]) echo $((v*1024));; [Mm]) echo $((v*1048576));; [Gg]) echo $((v*1073741824));; *) echo "$v";; esac; }
POST_B=$(to_bytes "$POST_MAX")
UPLOAD_MAX="$(( POST_B / 1048576 - 1 ))M"; [ "$POST_B" -lt 2097152 ] && UPLOAD_MAX="$(( POST_B / 2048 ))K"

# PHP minor version that reads a given conf.d / pool dir
version_for_path() {
  local p="$1" v
  v=$(printf '%s' "$p" | sed -n 's#.*/php/\([0-9]\.[0-9]\)/.*#\1#p')
  [ -n "$v" ] && { echo "$v"; return; }
  v=$(printf '%s' "$p" | sed -n 's#.*/php\([0-9]\)\([0-9]\)/.*#\1.\2#p')
  [ -n "$v" ] && { echo "$v"; return; }
  for b in php /usr/local/bin/php php-fpm /usr/local/sbin/php-fpm; do
    have "$b" || [ -x "$b" ] || continue
    v=$("$b" -n -v 2>/dev/null | sed -n '1s/^PHP \([0-9]\.[0-9]\).*/\1/p'); [ -n "$v" ] && { echo "$v"; return; }
  done
  echo "?"
}

ini_dirs() {
  local d
  for d in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cgi/conf.d /etc/php/*/cli/conf.d /etc/php/*/litespeed/conf.d \
           /usr/local/etc/php/conf.d /etc/php.d /etc/opt/remi/*/php.d /opt/cpanel/ea-php*/root/etc/php.d /usr/local/lsws/lsphp*/etc/php/*/mods-available; do
    [ -d "$d" ] && printf '%s\n' "$d"
  done
}
pool_files() {
  local f
  for f in /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/*/php-fpm.d/*.conf /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf; do
    [ -f "$f" ] || continue
    grep -E '^[[:space:]]*\[' "$f" | grep -vq '\[global\]' || continue   # only files defining a pool section
    printf '%s\n' "$f"
  done
}

dropin_content() { # $1 = php minor
  printf '%s\n' "$MARK_B" "; Official php.net temporary mitigations. Not a fix: update PHP." \
    "session.upload_progress.enabled = 0" "post_max_size = $POST_MAX" "upload_max_filesize = $UPLOAD_MAX"
  [ "$1" = 8.5 ] && echo "fatal_error_backtraces = 0"
  echo "$MARK_E"
}
pool_block() { # $1 = php minor
  printf '%s\n' "$MARK_B" "php_admin_flag[session.upload_progress.enabled] = off" \
    "php_admin_value[post_max_size] = $POST_MAX" "php_admin_value[upload_max_filesize] = $UPLOAD_MAX"
  [ "$1" = 8.5 ] && echo "php_admin_flag[fatal_error_backtraces] = off"
  [ "$MEMU" = 1 ] && echo "php_admin_value[memory_limit] = -1"
  echo "$MARK_E"
}
# Appends our block to the END of every pool section in the file (replacing an older block).
render_pool() { # file minor -> new content on stdout
  local blk; blk=$(pool_block "$2")
  awk -v mb="$MARK_B" -v me="$MARK_E" -v blk="$blk" '
    $0==mb {skip=1; next} skip && $0==me {skip=0; next} skip {next}
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { if (inpool) print blk; sec=$0; gsub(/[[:space:]\[\]]/,"",sec); inpool=(sec!="global") }
    {print}
    END { if (inpool) print blk }' "$1"
}

restart_cmds() {
  local u
  if have systemctl && [ -d /run/systemd/system ]; then
    for u in $(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(php[0-9.]*-fpm|php-fpm|ea-php[0-9]+-php-fpm|apache2|httpd|lsws|lshttpd|frankenphp)\.service$'); do
      echo "systemctl restart $u"
    done
  else
    local d c
    for d in /proc/[0-9]*; do
      c=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
      case "$c" in "php-fpm: master process"*) echo "kill -USR2 ${d#/proc/}   # graceful php-fpm reload";; esac
    done
    if grep -qsE '^(apache2|httpd)$' /proc/[0-9]*/comm; then
      have apachectl && echo "apachectl -k graceful" || echo "apache2ctl -k graceful"
    fi
  fi
}

do_restart() {
  local c; c=$(restart_cmds)
  [ -z "$c" ] && { echo "No running PHP worker services found to restart."; return; }
  echo "Restarting PHP workers:"; printf '%s\n' "$c" | while IFS= read -r line; do
    echo "  + $line"; sh -c "${line%%#*}" || echo "  ! failed: $line"
  done
}

# ---------- rollback ----------
if [ "$MODE" = rollback ]; then
  [ -z "$RB_TS" ] && RB_TS=$(find "$BK_ROOT" -mindepth 1 -maxdepth 1 -type d -name "[0-9]*" ! -name "*.rolledback" -printf "%f\n" 2>/dev/null | sort | tail -1)
  M="$BK_ROOT/$RB_TS/manifest"
  { [ -n "$RB_TS" ] && [ -r "$M" ]; } || { echo "No backup set found in $BK_ROOT"; exit 1; }
  echo "Rolling back backup set $RB_TS"
  while read -r act path; do
    case "$act" in
      modified) cp -p "$BK_ROOT/$RB_TS/files$path" "$path" && echo "  restored $path" ;;
      created) if grep -qF "$MARK_B" "$path" 2>/dev/null; then rm -f "$path" && echo "  removed  $path"; else echo "  skipped  $path (not ours)"; fi ;;
    esac
  done < "$M"
  mv "$BK_ROOT/$RB_TS" "$BK_ROOT/$RB_TS.rolledback"
  if [ "$RESTART" = 1 ]; then do_restart; else echo; echo "Restart needed to take effect:"; restart_cmds | sed 's/^/  /'; fi
  exit 0
fi

# ---------- plan / apply ----------
[ "$MODE" = apply ] && [ "$(id -u)" != 0 ] && { echo "--apply needs root (sudo)." >&2; exit 77; }
TS=$(date +%Y%m%d-%H%M%S); BK="$BK_ROOT/$TS"; changes=0
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "PHP2Shell temporary mitigations  mode=$MODE  post_max_size=$POST_MAX upload_max_filesize=$UPLOAD_MAX memory_limit=-1:$([ $MEMU = 1 ] && echo yes || echo no)"
echo "These are NOT a fix. Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or your distro backport) and restart workers."
echo

stage() { # path newfile
  local path="$1" new="$2" rel
  if [ -f "$path" ] && cmp -s "$path" "$new"; then echo "unchanged: $path"; return; fi
  changes=$((changes+1))
  if [ -f "$path" ]; then diff -u --label "a$path" --label "b$path" "$path" "$new"; else diff -u --label /dev/null --label "b$path" /dev/null "$new"; fi
  [ "$MODE" = apply ] || return 0
  mkdir -p "$BK/files"
  if [ -f "$path" ]; then
    rel="$BK/files$path"; mkdir -p "$(dirname "$rel")"; cp -p "$path" "$rel"; echo "modified $path" >> "$BK/manifest"
  else echo "created $path" >> "$BK/manifest"; fi
  cat "$new" > "$path.p2s.tmp" || return 1
  if [ -f "$path" ]; then chmod --reference="$path" "$path.p2s.tmp" 2>/dev/null; chown --reference="$path" "$path.p2s.tmp" 2>/dev/null; else chmod 0644 "$path.p2s.tmp"; fi
  mv "$path.p2s.tmp" "$path"
}

n=0
while IFS= read -r d; do
  [ -n "$d" ] || continue; n=$((n+1))
  dropin_content "$(version_for_path "$d")" > "$TMP/$n.ini"
  stage "$d/$DROPIN" "$TMP/$n.ini"
done <<EOT
$(ini_dirs)
EOT
while IFS= read -r f; do
  [ -n "$f" ] || continue; n=$((n+1))
  render_pool "$f" "$(version_for_path "$f")" > "$TMP/$n.conf"
  stage "$f" "$TMP/$n.conf"
done <<EOT
$(pool_files)
EOT

echo
if [ "$changes" = 0 ]; then echo "Nothing to change (mitigations already present or no PHP config found)."; exit 0; fi
if [ "$MODE" = dry ]; then
  echo "DRY-RUN: $changes file(s) would change. Nothing was written. Re-run with --apply after approval."
else
  echo "Applied $changes change(s). Backups + manifest: $BK   Rollback: $0 --rollback $TS"
  # validate FPM config; auto-rollback if invalid
  for b in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm /usr/sbin/php-fpm; do
    [ -x "$b" ] || continue
    if ! "$b" -t >/dev/null 2>&1; then echo "! $b -t failed; rolling back"; "$0" --rollback "$TS" --backup-dir "$BK_ROOT"; exit 1; fi
  done
fi
echo "Workers must be restarted (php.net: restart every worker):"
restart_cmds | sed 's/^/  /'
if [ "$MODE" = apply ] && [ "$RESTART" = 1 ]; then do_restart; fi
exit 0
