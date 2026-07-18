#!/usr/bin/env python3
"""
Variante ponctuelle de wazuh_ai_triage.py pour soumettre au LLM une alerte
precise (identifiee par rule.id), independamment du seuil global
LLM_INVOCATION_THRESHOLD_LEVEL -- utilisee pour le scenario brute force SSH
(regle 5710, niveau 5) qui reste normalement sous le seuil Gemma (8) et sur
le chemin Shuffle (5-7), mais dont on veut aussi une preuve du chemin Gemma
a des fins de documentation.

Reutilise l'idempotence et le schema de validation de wazuh_ai_triage.py :
une alerte deja traitee (meme _es_id present dans l'etat local) n'est pas
retraitee, et une reponse LLM qui ne respecte pas TriageResult ne cree pas
de cas. Outil de demonstration cible, pas un composant du pipeline courant :
il traite explicitement une alerte a la fois, choisie par rule_id.

Usage :
  python3 triage_single_alert.py <rule_id> [--dry-run] [--no-create-case]

  --dry-run          affiche l'alerte selectionnee et le resultat du triage
                      LLM, mais ne cree aucun cas TheHive et ne marque rien
                      comme traite.
  --no-create-case    execute le triage LLM et l'enregistre comme traite,
                      mais ne cree pas de cas TheHive (utile pour tester le
                      prompt sans polluer TheHive).
"""

import argparse
import sys

import requests
from wazuh_ai_triage import (
    WAZUH_INDEXER_PASSWORD,
    WAZUH_INDEXER_URL,
    WAZUH_INDEXER_USER,
    already_processed,
    baseline_criticality,
    create_thehive_case,
    init_state_db,
    log,
    mark_processed,
    triage_with_llm,
    validate_configuration,
)


def fetch_by_rule_id(rule_id: str) -> list[dict]:
    """Requete ciblee sur rule.id, pour contourner le bruit qui peut evincer
    une alerte peu frequente du top-N tri par recence de fetch_recent_alerts.
    Retourne les alertes triees par recence (la plus recente en premier) ;
    l'appelant est responsable de confirmer explicitement laquelle traiter."""
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
    alerts = []
    for hit in resp.json()["hits"]["hits"]:
        source = hit["_source"]
        source["_es_id"] = hit["_id"]
        alerts.append(source)
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rule_id", help="rule.id Wazuh a cibler (ex: 5710)")
    parser.add_argument("--dry-run", action="store_true", help="n'ecrit rien (ni cas TheHive, ni etat d'idempotence)")
    parser.add_argument("--no-create-case", action="store_true", help="triage LLM sans creer de cas TheHive")
    args = parser.parse_args()

    if not args.dry_run:
        validate_configuration()

    matching = fetch_by_rule_id(args.rule_id)
    if not matching:
        log.error("Aucune alerte recente avec rule.id=%s", args.rule_id)
        sys.exit(1)

    alert = matching[0]
    alert_id = alert.get("_es_id", "")
    log.info(
        "Alerte selectionnee (la plus recente parmi %d) : _id=%s, timestamp=%s, description=%r",
        len(matching), alert_id, alert.get("timestamp"), alert.get("rule", {}).get("description"),
    )

    state_conn = None
    try:
        if not args.dry_run:
            state_conn = init_state_db()
            if alert_id and already_processed(state_conn, alert_id):
                log.info("Alerte %s deja traitee precedemment (idempotence) -- rien a faire.", alert_id)
                return

        criticite = baseline_criticality(alert)
        triage = triage_with_llm(alert)
        if triage is None:
            log.error("Reponse LLM invalide ou Ollama injoignable -- aucun cas cree.")
            if state_conn and not args.dry_run:
                # failed_retryable, pas "processed" : un echec transitoire ne doit pas empecher
                # une nouvelle tentative ulterieure (meme bug que dans wazuh_ai_triage.py, corrige
                # ici de la meme facon -- voir ce script pour le detail du raisonnement).
                mark_processed(state_conn, alert_id, None, status="failed_retryable")
            sys.exit(1)

        log.info("%s -> criticite (hybride/baseline)=%s, mitre=%s", triage.incident_type, criticite, triage.mitre_technique)

        if args.dry_run:
            log.info("[--dry-run] Aucun cas TheHive cree, aucun etat enregistre.")
            return

        case_id = None
        status = "processed"
        if not args.no_create_case:
            result = create_thehive_case(alert, triage, criticite)
            case_id = result["case_id"]
            status = "case_created"
            if result["created"]:
                log.info("-> cas TheHive cree : %s", case_id)
            else:
                log.info("-> cas TheHive existant reutilise (doublon local evite) : %s", case_id)
        else:
            log.info("[--no-create-case] Triage effectue, aucun cas TheHive cree.")

        mark_processed(state_conn, alert_id, case_id, status=status)
    finally:
        if state_conn:
            state_conn.close()


if __name__ == "__main__":
    sys.exit(main())
