#!/usr/bin/env python3
"""
Construit le jeu de donnees labellise (S5) a partir des scenarios de
generate_test_dataset.sh et des alertes reellement indexees par Wazuh.

Pour chaque scenario (fenetre temporelle + reference attendue), recupere les
alertes Wazuh correspondantes et leur associe le label de reference.

Entree  : reference_dataset.jsonl (produit par generate_test_dataset.sh)
Sortie  : labeled_dataset.json
"""

import json
import os
import sys
from datetime import datetime, timedelta

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")

REFERENCE_FILE = os.path.expanduser("~/reference_dataset.jsonl")
OUTPUT_FILE = os.path.expanduser("~/labeled_dataset.json")

BUFFER_SECONDS = 5  # marge apres la fin du scenario pour laisser Wazuh indexer


def fetch_alerts_in_window(start: str, end: str) -> list[dict]:
    end_dt = datetime.fromisoformat(end) + timedelta(seconds=BUFFER_SECONDS)
    query = {
        "size": 50,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "range": {
                "timestamp": {"gte": start, "lte": end_dt.isoformat()}
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
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def main() -> None:
    labeled = []
    with open(REFERENCE_FILE) as f:
        scenarios = [json.loads(line) for line in f if line.strip()]

    for scenario in scenarios:
        alerts = fetch_alerts_in_window(scenario["start"], scenario["end"])
        print(f"[{scenario['scenario']}] {len(alerts)} alerte(s) trouvee(s)")
        for alert in alerts:
            labeled.append(
                {
                    "scenario": scenario["scenario"],
                    "alert": alert,
                    "reference": {
                        "incident_type": scenario["incident_type_ref"],
                        "criticite": scenario["criticite_ref"],
                        "mitre_tactic": scenario["mitre_tactic_ref"],
                        "mitre_technique": scenario["mitre_technique_ref"],
                    },
                }
            )

    with open(OUTPUT_FILE, "w") as f:
        json.dump(labeled, f, indent=2, default=str)

    print(f"\n[+] {len(labeled)} alerte(s) labellisee(s) ecrite(s) dans {OUTPUT_FILE}")


if __name__ == "__main__":
    sys.exit(main())
