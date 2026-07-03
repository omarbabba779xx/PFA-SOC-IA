#!/bin/bash
# Jeu de test INDEPENDANT (held-out) pour l'evaluation S5 : scenarios jamais
# utilises pour calibrer le prompt few-shot, incluant des cas volontairement
# ambigus/bruites pour tester la generalisation reelle (pas la memorisation).
set -u
REF_FILE=~/reference_holdout.jsonl
> "$REF_FILE"

log_scenario() {
  local name="$1" start="$2" end="$3" incident_type="$4" criticite="$5" tactic="$6" technique="$7"
  echo "{\"scenario\":\"$name\",\"start\":\"$start\",\"end\":\"$end\",\"incident_type_ref\":\"$incident_type\",\"criticite_ref\":\"$criticite\",\"mitre_tactic_ref\":\"$tactic\",\"mitre_technique_ref\":\"$technique\"}" >> "$REF_FILE"
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%S"; }

echo "[1/6] Sudo : deux echecs de frappe puis succes (utilisateur legitime distrait)"
START=$(now_iso)
echo "typo1" | sudo -S -k true 2>/dev/null
echo "typo2" | sudo -S -k true 2>/dev/null
sudo -n true 2>/dev/null; sudo whoami >/dev/null 2>&1
END=$(now_iso)
log_scenario "holdout_sudo_typo_then_success" "$START" "$END" "Echecs de frappe puis succes sudo (legitime)" "basse" "Privilege Escalation" "T1548"
sleep 3

echo "[2/6] Creation de compte avec repertoire home (onboarding legitime, pas -M)"
START=$(now_iso)
sudo useradd -m holdout_onboard1 2>/dev/null
END=$(now_iso)
log_scenario "holdout_user_onboarding" "$START" "$END" "Creation de compte (onboarding legitime)" "moyenne" "Persistence" "T1136"
sleep 3

echo "[3/6] Suppression de compte de service obsolete (nettoyage de routine)"
START=$(now_iso)
sudo userdel holdout_onboard1 2>/dev/null
END=$(now_iso)
log_scenario "holdout_user_cleanup" "$START" "$END" "Suppression de compte (nettoyage de routine)" "basse" "Impact" "T1531"
sleep 3

echo "[4/6] Tache cron benigne (rotation de logs, pas obfusquee)"
START=$(now_iso)
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/sbin/logrotate /etc/logrotate.conf # pfa-holdout-benign") | crontab -
END=$(now_iso)
log_scenario "holdout_cron_benign" "$START" "$END" "Tache planifiee benigne (logrotate)" "basse" "Persistence" "T1053"
sleep 3
crontab -r 2>/dev/null

echo "[5/6] Decodage base64 vers bash d'un contenu benin (pas une charge malveillante)"
START=$(now_iso)
echo "ZGF0ZQ==" | base64 -d | bash 2>/dev/null
END=$(now_iso)
log_scenario "holdout_base64_benign" "$START" "$END" "Commande encodee benigne (date)" "moyenne" "Defense Evasion" "T1140"
sleep 3

echo "[6/6] Connexions SSH valides a frequence inhabituelle (script d'automatisation legitime)"
START=$(now_iso)
for i in 1 2 3 4 5; do
  ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 soc@localhost "whoami" 2>/dev/null
done
END=$(now_iso)
log_scenario "holdout_ssh_valid_frequent" "$START" "$END" "Connexions SSH frequentes compte valide (legitime)" "basse" "Initial Access" "T1078"

echo "Termine. Reference ecrite dans $REF_FILE"
cat "$REF_FILE"
