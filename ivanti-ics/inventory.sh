#!/usr/bin/env bash
# Defensive inventory only - Ivanti Connect Secure CVE-2026-104935/111357/118527
echo "== Lab identity =="; hostname; date '+%Y-%m-%d %H:%M %Z'; uname -srm
echo; echo "== ICS appliance check (read-only) =="
found=0; for p in /home/runtime /home/webserver /data/runtime; do [ -e "$p" ] && { echo "present: $p"; found=1; }; done
[ $found -eq 0 ] && echo "Ivanti Connect Secure appliance NOT present on this Linux lab host (inventory negative)"
echo; echo "== Patch matrix (reference only, per CISA/Ivanti) =="
printf '%-26s %-12s\n' "Affected (CISA)" "Fixed build"
printf '%-26s %-12s\n' "25.1.1.2 and prior" "25.1.1.3" "25.1.2.2 and prior" "see Ivanti advisory" "22.8R2.5 and prior" "22.8R2.6"
echo "22.8 line EOL: 2027-01-31"
echo "KEV: 104935 (2026-10-13) | 111357 + 118527 (2026-10-30; due ~11-02 / ~11-13)"
