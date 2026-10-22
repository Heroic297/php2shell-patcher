# Simulated new-owner run: non-technical hosted path (2026-10-21, ~9:50 PM ET)

Sources actually read:
- Hostinger blog, "Hostinger deploys protections against php2shell PHP vulnerabilities", published 2026-10-21 20:33 UTC: https://www.hostinger.com/blog/protecting-php2shell/
- InMotion Hosting status, "Security Maintenance: PHP Configuration Updates", latest update 2026-10-22 01:02 UTC: https://status.inmotionhosting.com/incidents/5b3dee2d-6b8e-4a58-88e4-812ef43ef43a

## Owner A: WordPress site on Hostinger shared/web hosting
Plain-language summary the bot would give:
> Hostinger runs the software your website is built on, and they say they've already fixed this for every plan except VPS. They're blocking the known attack and installing the fix, so you don't need to do anything. If your site is still on an old version (8.2 or older), it's worth moving to 8.3 or newer in Hostinger's dashboard under Websites → Dashboard → PHP Configuration. Check that your theme and plugins support it first.
Result: **safe (host-managed)**. If Owner A is on a Hostinger **VPS**: action needed. They update PHP and restart it themselves, which is the own-server path.

## Owner B: site on InMotion shared hosting
Plain-language summary:
> InMotion is still rolling out the fix. As of 9:02 PM ET they say the upgrades are done on shared and dedicated servers and still running on VPS servers. In the meantime they've turned off the setting the attack uses. Your site should be covered, but it's worth asking them to confirm.
Result: **waiting on host / confirm**.

Draft support message (the owner sends it; the bot never sends it):
> Subject: PHP2Shell (CVE-2026-109618 / CVE-2026-109619) status for my site
>
> Hi, my site is [example.com] on my [plan name] account. Could you confirm:
> 1. Which PHP version my site runs now, and whether it's patched for CVE-2026-109618 and CVE-2026-109619 (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or a CloudLinux/vendor backport)?
> 2. When the PHP workers on my server were restarted after the update?
> 3. Whether session.upload_progress is disabled until the patch is in place, and whether I need to do anything on my side.
> Thank you!
