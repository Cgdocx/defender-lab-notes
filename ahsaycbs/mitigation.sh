#!/usr/bin/env bash
# Mitigation checklist from Ahsay / ThaiCERT — documentation only.
set -euo pipefail
cd /lab/ahsaycbs
cat > conf/mitigation-checklist.txt <<'CHK'
[ ] Apply Hotfix 10.3.4.45 (v10) or 9.15.2.70 (v9); restart server
[ ] Restrict AhsayCBS admin UI to VPN / allowlisted IPs (no direct Internet)
[ ] Review %CBS%\webapps for unexpected .jsp / random folders
[ ] Review unauthorized RPS receivers and Admin accounts
[ ] Hunt MicrosoftEdgeUpdateSvc / edge.exe / Taskgmr.ps1
[ ] Block imagefiles-backup.oss-ap-southeast-7.aliyuncs.com (bucket only)
[ ] Alert on outbound TCP/8029 to xmr.kryptex.network
[ ] If IoCs found: isolate -> preserve evidence -> rotate creds
[ ] rebuild host (OS + CBS + hotfix), restore AutoSave from >= 1 day before compromise
CHK
echo "=== mitigation checklist (documentation) ==="
date -R
sed -n '1,12p' conf/mitigation-checklist.txt
echo
echo "mitigation checklist ready."
