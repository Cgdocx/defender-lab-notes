#!/usr/bin/env bash
# Defensive public IoC cues (Huntress) — names/hashes only. No sample execution.
set -euo pipefail
cd /lab/ahsaycbs
echo "=== hunt: public IoC cues (lookup only) ==="
date -R
hostname
echo
echo "# SHA-256 (public: Huntress)"
echo "edge.exe_XMRig"
echo "  4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d"
echo "msedge.exe_NSSM"
echo "  05f69ae6b2b89c1c4dcf836bff032232f11bf0109f2b498e2345045d06139034"
echo "Taskgmr.ps1"
echo "  481728a7c9c4c02be07051d9c1958d902ea6397ebb8952ab83944818e3d25d21"
echo
echo "# service / filename / network hunt cues (names only)"
printf '%s\n' \
  'MicrosoftEdgeUpdateSvc' \
  'edge.exe in %TEMP%' \
  'msedge.exe in %TEMP%' \
  'unknown *.jsp under %CBS%\webapps' \
  'outbound TCP 8029 -> xmr.kryptex.network' \
  'imagefiles-backup.oss-ap-southeast-7.aliyuncs.com (bucket only)'
echo
echo "hunt done — if matches on authorized Windows CBS host: isolate + preserve evidence."
