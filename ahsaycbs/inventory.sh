#!/usr/bin/env bash
# Defensive inventory: look for AhsayCBS paths (read-only). No exploit traffic.
set -euo pipefail
cd /lab/ahsaycbs
echo "=== inventory: AhsayCBS path check (defensive) ==="
date -R
printf 'hostname: '; hostname
printf 'uname: '; uname -srm
echo
echo "# OS"
head -3 /etc/os-release
echo
echo "# look for AhsayCBS install paths (read-only)"
echo "# Windows: %CBS%   Linux: \$CBS / /opt/AhsayCBS"
ls -ld "/Program Files/AhsayCBS" "/opt/AhsayCBS" "${CBS:-}" 2>/dev/null \
  || echo "AhsayCBS path not present on this lab host (inventory negative)"
echo
echo "# Expected hotfix builds (Ahsay / ThaiCERT — not proof of local patch state)"
printf '%s\n' 'v10 -> Hotfix 10.3.4.45' 'v9  -> Hotfix 9.15.2.70' 'v7/v8 -> upgrade to 9.15.0.0 then 9.15.2.70'
echo "# Windows: apply hotfix Run as administrator, then restart"
echo
echo "inventory done."
