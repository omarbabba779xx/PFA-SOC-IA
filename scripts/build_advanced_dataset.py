#!/usr/bin/env python3
"""
Construit le jeu de test labellise pour les 4 scenarios avances (S8), en
recuperant les alertes reelles depuis l'indexeur Wazuh.

Revision : la version precedente ciblait un index date en dur
(wazuh-alerts-4.x-2026.07.03) et ecrivait toujours dans /home/soc,
empechant quiconque en dehors de cette VM precise de rejouer le script.
Cible desormais le pattern d'index standard (wazuh-alerts-4.x-*) filtre
par plage temporelle, et ecrit dans un chemin configurable.

Variables d'environnement :
  WAZUH_INDEXER_URL       (defaut: https://localhost:9200)
  WAZUH_INDEXER_USER      (defaut: admin)
  WAZUH_INDEXER_PASSWORD  (defaut: lu depuis ~/.wazuh_indexer_password si absent)
  DATASET_LOOKBACK_DAYS   (defaut: 7) -- fenetre de recherche des alertes
  DATASET_AUDIT_UID       (defaut: 1000) -- UID Linux du compte de simulation
  OUTPUT_FILE             (defaut: ~/labeled_dataset_advanced.json)
"""

import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
if not WAZUH_INDEXER_PASSWORD:
    password_file = os.path.expanduser("~/.wazuh_indexer_password")
    if os.path.exists(password_file):
        WAZUH_INDEXER_PASSWORD = open(password_file).read().strip()
    else:
        print("[!] WAZUH_INDEXER_PASSWORD non defini et ~/.wazuh_indexer_password introuvable", file=sys.stderr)
        sys.exit(1)

LOOKBACK_DAYS = int(os.environ.get("DATASET_LOOKBACK_DAYS", "7"))
AUDIT_UID = os.environ.get("DATASET_AUDIT_UID", "1000")
OUTPUT_FILE = os.path.expanduser(os.environ.get("OUTPUT_FILE", "~/labeled_dataset_advanced.json"))

RULE_REFS = {
    "100099": {"incident_type": "Recuperation de payload suspect (proxy phishing)", "criticite": "haute", "mitre_tactic": "Command and Control", "mitre_technique": "T1105"},
    "100101": {"incident_type": "Execution PowerShell encodee suspecte", "criticite": "critique", "mitre_tactic": "Execution", "mitre_technique": "T1059.001"},
    "100103": {"incident_type": "Requetes repetees vers la meme destination (C2 beaconing simule)", "criticite": "haute", "mitre_tactic": "Command and Control", "mitre_technique": "T1071"},
    "100105": {"incident_type": "Connexions SSH successives avec elevation (mouvement lateral simule)", "criticite": "haute", "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.004"},
}
SCENARIO_NAMES = {
    "100099": "phishing_url_proxy",
    "100101": "powershell_suspicious",
    "100103": "c2_beaconing_simulated",
    "100105": "lateral_movement_simulated",
}


def main() -> None:
    labeled = []
    for rule_id, ref in RULE_REFS.items():
        query = {
            "size": 6,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"rule.id": rule_id}},
                        {"term": {"data.audit.auid": AUDIT_UID}},
                        {"range": {"timestamp": {"gte": f"now-{LOOKBACK_DAYS}d"}}},
                    ]
                }
            },
        }
        resp = requests.get(
            f"{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
            json=query,
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
        if not hits:
            print(f"[!] Aucune alerte trouvee pour rule.id={rule_id} sur les {LOOKBACK_DAYS} derniers jours", file=sys.stderr)
        for h in hits:
            labeled.append({"scenario": SCENARIO_NAMES[rule_id], "alert": h["_source"], "reference": ref})

    with open(OUTPUT_FILE, "w") as f:
        json.dump(labeled, f, indent=2, default=str)
    print(f"[+] {len(labeled)} alerte(s) reelle(s) collectee(s) (avec contenu execve complet) pour les 4 scenarios avances -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
