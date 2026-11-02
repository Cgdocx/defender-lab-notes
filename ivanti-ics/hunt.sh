#!/usr/bin/env bash
# Defensive hunt cues only - no exploit traffic, no payloads
echo "== Hunt cues (review on authorized appliance logs / evidence copies) =="
echo "[1] Web access logs: requests to login/welcome.cgi where requested URL and"
echo "    X-DSCGI-PATH value (if logged) disagree -> auth-confusion indicator (high level)"
echo "[2] Integrity Checker Tool (ICT): may NOT detect CVE-2026-104935 (in-memory)"
echo "    -> clean ICT result is not proof of no compromise"
echo "[3] Memory forensics / vendor-assisted triage required (BOD 26-04)"
echo "[4] Unexpected files under /home/runtime/tmp/ (path from public reporting)"
echo "[5] Unexpected root child processes / maintenance tasks, new admin sessions"
echo "[6] Outbound connections from appliance to unknown hosts; config/cred export"
echo; echo "== Local lab check =="
[ -d /home/runtime/tmp ] && ls -la /home/runtime/tmp || echo "/home/runtime/tmp not present (lab host is not ICS) - negative"
