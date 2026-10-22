# Proposed edits to the bot skills (found during the simulated new-owner run)

## php2shell-patcher/SKILL.md
1. Replace the "Tools:" block with:
   Tools: scripts at https://github.com/Heroic297/php2shell-patcher, pinned tag v1.1.0. Download each with
   `curl -fsSLO https://raw.githubusercontent.com/Heroic297/php2shell-patcher/v1.1.0/<file>` and run `sha256sum -c` before running it:
   - php2shell_check.sh 694ff2b43b0322a3fd27258fa5a25ea7467ca88ac57cd0e82aced0e98b1a43cb
   - php2shell_mitigate.sh fa0dd6addfa90a8d7ee33eecbe24906fcbd8b9bc38e1b2375bfaf95c3869ee9b
   - php2shell_verify.sh 703d758939e49bf942e35db97f26d6e4890005be520daed5d3292d4dc7c10768
   If a hash mismatches or the download is not HTTP 200, stop and tell the user.
2. Technical step 2, add: "Run check with sudo on the host so it also scans running Docker containers. mitigate and verify act only on the system they run on. For a container, copy the scripts in (`docker cp`) and run them with `docker exec`, or run them on the VM/host where PHP lives."
3. Technical step 3, add the upgrade commands per platform: Debian/Ubuntu `apt-get install --only-upgrade 'php8.*'`, RHEL/Rocky/Alma `dnf upgrade 'php*'` (remi: `dnf upgrade 'php8*-php*'`), official images: bump the tag (e.g. php:8.3.36-fpm) and redeploy. "If the distro has no fixed build yet, as with Rocky 9 AppStream php 8.2.33 on 10/21, use the temporary mitigations and recheck daily."
4. Technical step 5, replace "Then `php2shell_verify.sh`; it must PASS" with: "After an upgrade, run `php2shell_mitigate.sh --restart-only` (or the printed restart command), then `php2shell_verify.sh`. It must PASS. After mitigations alone, verify still FAILs on the version line. That is expected. Report it as 'temporarily protected, not fixed' and keep the host on the upgrade list."
5. Technical step 5, add: "FrankenPHP is never restarted automatically. Ask before restarting its service or container. LiteSpeed: `--restart` runs `lswsctrl restart` and stops lsphp workers."
6. Technical step 5, make "Check the site still returns HTTP 200" concrete: "`curl -s -o /dev/null -w '%{http_code}' https://<site>/` from the user's computer. For an FPM-only container, use `cgi-fcgi` against port 9000 with a test script. If the status changed from before, run `--rollback --restart` and tell the user."
7. Non-technical step 2: "Ask which plan they're on (shared/managed vs VPS/dedicated). Hosts treat them differently: Hostinger fixes everything except VPS, and InMotion's VPS fleet was still in progress. Quote the notice's timestamp, and say statuses change."

## php2shell-getting-started/SKILL.md
8. Question 2: replace "Ask them to register the computer if needed" with "If it isn't listed in ListMachines, ask them to register it in Grok Bot (desktop app). Commands on a server run there, never on my own computer, except throwaway test containers."
9. Add after question 1: "If they host with a company but have a VPS or dedicated server, treat it as Own server."
10. Add: "Before any change, say in one line what will happen and that you'll ask first."
