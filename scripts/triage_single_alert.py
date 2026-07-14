#!/usr/bin/env python3
"""
Variante ponctuelle de wazuh_ai_triage.py pour soumettre au LLM une alerte
precise (identifiee par rule.id), independamment du seuil global
LLM_INVOCATION_THRESHOLD_LEVEL -- utilisee pour le scenario brute force SSH
(regle 5710, niveau 5) qui reste normalement sous le seuil Gemma (8) et sur
le chemin Shuffle (5-7), mais dont on veut aussi une preuve du chemin Gemma
a des fins de documentation.

Usage : python3 triage_single_alert.py <rule_id>
"""

import sys

import requests

from wazuh_ai_triage import (
    WAZUH_INDEXER_PASSWORD,
    WAZUH_INDEXER_URL,
    WAZUH_INDEXER_USER,
    baseline_criticality,
    create_thehive_case,
    triage_with_llm,
)


def fetch_by_rule_id(rule_id: str) -> list[dict]:
    """Requete ciblee sur rule.id, pour contourner le bruit qui peut evincer
    une alerte peu frequente du top-N tri par recence de fetch_recent_alerts."""
    query = {
        "size": 5,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"term": {"rule.id": rule_id}},
    }
    resp = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=False,
        timeout=60,
    )
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def main() -> None:
    target_rule_id = sys.argv[1]
    matching = fetch_by_rule_id(target_rule_id)
    if not matching:
        print(f"[!] Aucune alerte recente avec rule.id={target_rule_id}")
        return
    alert = matching[0]
    criticite = baseline_criticality(alert)
    triage = triage_with_llm(alert)
    print(f"  - {triage.get('incident_type')} -> criticite (hybride/baseline)={criticite}")
    case_id = create_thehive_case(alert, triage, criticite)
    print(f"    -> cas TheHive cree : {case_id}")


if __name__ == "__main__":
    sys.exit(main())
