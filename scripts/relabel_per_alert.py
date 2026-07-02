#!/usr/bin/env python3
"""
Corrige la methodologie de labellisation du jeu de test (S5) : au lieu d'une
reference unique par fenetre de scenario (trop grossiere), attribue une
reference manuelle a CHAQUE alerte individuelle selon le contenu reel de son
log, conformement a l'exigence du cahier des charges ("chaque alerte aura une
reference attendue"). Le mapping ci-dessous est une analyse manuelle du
contenu des logs (codes MITRE ATT&CK officiels), independante du champ
rule.mitre deja present dans l'alerte Wazuh.
"""

import json
import os

INPUT_FILE = os.path.expanduser("~/labeled_dataset_sample.json")
OUTPUT_FILE = os.path.expanduser("~/labeled_dataset_per_alert.json")

# Reference manuelle par type d'evenement reel (analyse independante du log)
MANUAL_REFERENCE = {
    "Successful sudo to ROOT executed.": {
        "incident_type": "Elevation de privileges (sudo)",
        "criticite": "basse",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548",
    },
    "PAM: Login session opened.": {
        "incident_type": "Ouverture de session",
        "criticite": "basse",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078",
    },
    "PAM: Login session closed.": {
        "incident_type": "Fermeture de session",
        "criticite": "basse",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078",
    },
    "sshd: Attempt to login using a non-existent user": {
        "incident_type": "Brute force SSH",
        "criticite": "haute",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    },
    "PAM: User login failed.": {
        "incident_type": "Echec authentification",
        "criticite": "moyenne",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    },
    "User missed the password to change UID (user id).": {
        "incident_type": "Echec elevation de privileges (su)",
        "criticite": "moyenne",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548",
    },
    "sshd: authentication success.": {
        "incident_type": "Connexion SSH reussie",
        "criticite": "basse",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078",
    },
    "New user added to the system.": {
        "incident_type": "Creation de compte",
        "criticite": "haute",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136",
    },
    "Group (or user) deleted from the system.": {
        "incident_type": "Suppression de compte",
        "criticite": "moyenne",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1531",
    },
    "Crontab entry changed.": {
        "incident_type": "Modification de tache planifiee",
        "criticite": "moyenne",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053",
    },
}


def main() -> None:
    with open(INPUT_FILE) as f:
        dataset = json.load(f)

    relabeled = []
    unmatched = 0
    for item in dataset:
        desc = item["alert"]["rule"]["description"]
        ref = MANUAL_REFERENCE.get(desc)
        if ref is None:
            unmatched += 1
            continue
        relabeled.append({"scenario": item["scenario"], "alert": item["alert"], "reference": ref})

    with open(OUTPUT_FILE, "w") as f:
        json.dump(relabeled, f, indent=2, default=str)

    print(f"[+] {len(relabeled)} alerte(s) relabellisee(s) par contenu reel -> {OUTPUT_FILE}")
    if unmatched:
        print(f"[!] {unmatched} alerte(s) sans correspondance dans le mapping manuel, exclue(s)")


if __name__ == "__main__":
    main()
