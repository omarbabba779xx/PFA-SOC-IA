#!/bin/bash
# Genere une serie de scenarios varies pour constituer le jeu de 30-50 alertes
# labellisees (evaluation S5 du PFA). Chaque scenario est enregistre avec un
# horodatage de debut/fin et une reference attendue dans reference_dataset.jsonl

set -u
REF_FILE=~/reference_dataset.jsonl
> "$REF_FILE"

log_scenario() {
  local name="$1" start="$2" end="$3" incident_type="$4" criticite="$5" tactic="$6" technique="$7"
  echo "{\"scenario\":\"$name\",\"start\":\"$start\",\"end\":\"$end\",\"incident_type_ref\":\"$incident_type\",\"criticite_ref\":\"$criticite\",\"mitre_tactic_ref\":\"$tactic\",\"mitre_technique_ref\":\"$technique\"}" >> "$REF_FILE"
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%S"; }

echo "[1/9] Brute force SSH (utilisateurs invalides)"
START=$(now_iso)
for i in 1 2 3 4 5 6; do
  ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 -o PreferredAuthentications=publickey "bfuser$i@localhost" "true" 2>/dev/null
done
END=$(now_iso)
log_scenario "ssh_bruteforce" "$START" "$END" "Brute force SSH" "haute" "Initial Access" "T1110"
sleep 3

echo "[2/9] Connexions SSH valides repetees (compte legitime)"
START=$(now_iso)
for i in 1 2 3; do
  ssh -i ~/.ssh/id_ed25519 2>/dev/null -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 soc@localhost "whoami" 2>/dev/null || \
  ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 -o PreferredAuthentications=publickey soc@localhost "whoami" 2>/dev/null
done
END=$(now_iso)
log_scenario "ssh_valid_repeated" "$START" "$END" "Connexions repetees compte valide" "basse" "Initial Access" "T1078"
sleep 3

echo "[3/9] Commandes sudo legitimes"
START=$(now_iso)
sudo -n true 2>/dev/null; sudo whoami >/dev/null 2>&1; sudo ls /root >/dev/null 2>&1; sudo id >/dev/null 2>&1
END=$(now_iso)
log_scenario "sudo_success" "$START" "$END" "Utilisation sudo legitime" "basse" "Privilege Escalation" "T1548"
sleep 3

echo "[4/9] Tentatives sudo echouees (mauvais mot de passe)"
START=$(now_iso)
for i in 1 2 3 4; do
  echo "wrongpass$i" | sudo -S -k true 2>/dev/null
done
END=$(now_iso)
log_scenario "sudo_failed" "$START" "$END" "Echecs authentification sudo" "moyenne" "Privilege Escalation" "T1548"
sleep 3

echo "[5/9] Tentatives su echouees"
START=$(now_iso)
for i in 1 2 3; do
  echo "wrongpass$i" | su - root -c "true" 2>/dev/null
done
END=$(now_iso)
log_scenario "su_failed" "$START" "$END" "Echecs authentification su" "moyenne" "Privilege Escalation" "T1548"
sleep 3

echo "[6/9] Creation de compte utilisateur"
START=$(now_iso)
sudo useradd -M testaccount1 2>/dev/null
sudo useradd -M testaccount2 2>/dev/null
END=$(now_iso)
log_scenario "user_creation" "$START" "$END" "Creation de compte" "haute" "Persistence" "T1136"
sleep 3

echo "[7/9] Suppression de compte utilisateur"
START=$(now_iso)
sudo userdel testaccount1 2>/dev/null
sudo userdel testaccount2 2>/dev/null
END=$(now_iso)
log_scenario "user_deletion" "$START" "$END" "Suppression de compte" "moyenne" "Impact" "T1531"
sleep 3

echo "[8/9] Creation de tache planifiee (cron)"
START=$(now_iso)
(crontab -l 2>/dev/null; echo "*/30 * * * * /usr/bin/true # pfa-test") | crontab -
END=$(now_iso)
log_scenario "cron_creation" "$START" "$END" "Creation tache planifiee" "moyenne" "Persistence" "T1053"
sleep 3
crontab -r 2>/dev/null

echo "[9/9] Commande suspecte (decodage base64 vers bash)"
START=$(now_iso)
echo "ZWNobyB0ZXN0" | base64 -d | bash 2>/dev/null
echo "ZWNobyB0ZXN0Mg==" | base64 -d | bash 2>/dev/null
END=$(now_iso)
log_scenario "base64_decode_exec" "$START" "$END" "Commande obfusquee" "haute" "Defense Evasion" "T1140"

echo "Termine. Reference ecrite dans $REF_FILE"
cat "$REF_FILE"
