#!/usr/bin/env python3
"""
Evaluation experimentale (S5) : compare le triage assiste par LLM (Mistral 7B)
a une baseline classique basee sur les regles de correlation natives de Wazuh
(rule.level, rule.mitre), par rapport a une reference etablie manuellement
lors de la generation des scenarios de test.

Entree  : labeled_dataset_sample.json (alerte + reference manuelle)
Sortie  : evaluation_results.json + resume des metriques sur stdout
"""

import json
import os
import sys
import time

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:7b-instruct-q4_0")

DATASET_FILE = os.path.expanduser("~/labeled_dataset_sample.json")
OUTPUT_FILE = os.path.expanduser("~/evaluation_results.json")

CRITICALITY_ORDER = ["basse", "moyenne", "haute", "critique"]

TRIAGE_PROMPT_TEMPLATE = """Tu es un assistant de triage SOC. Analyse l'alerte suivante et
reponds UNIQUEMENT en JSON valide avec les champs : incident_type, criticite
(basse/moyenne/haute/critique), mitre_tactic, mitre_technique, resume, recommandation.

Alerte Wazuh :
- Regle : {rule_description} (niveau {rule_level})
- Groupes : {rule_groups}
- Agent : {agent_name}
- Horodatage : {timestamp}

Reponds uniquement avec le JSON, sans texte autour.
"""


def baseline_classify(alert: dict) -> dict:
    """Classification baseline : regles de correlation natives de Wazuh (rule.level + rule.mitre)."""
    level = alert.get("rule", {}).get("level", 0)
    if level >= 12:
        criticite = "critique"
    elif level >= 9:
        criticite = "haute"
    elif level >= 5:
        criticite = "moyenne"
    else:
        criticite = "basse"

    mitre = alert.get("rule", {}).get("mitre", {})
    technique_id = mitre.get("id", [None])[0]
    tactic = mitre.get("tactic", [None])[0]

    return {
        "incident_type": alert.get("rule", {}).get("description", "N/A"),
        "criticite": criticite,
        "mitre_tactic": tactic,
        "mitre_technique": technique_id,
    }


def llm_classify(alert: dict) -> tuple[dict, float]:
    """Classification par le LLM local. Retourne (resultat, duree_secondes)."""
    rule = alert.get("rule", {})
    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        rule_description=rule.get("description", "N/A"),
        rule_level=rule.get("level", "N/A"),
        rule_groups=", ".join(rule.get("groups", [])),
        agent_name=alert.get("agent", {}).get("name", "N/A"),
        timestamp=alert.get("timestamp", "N/A"),
    )
    start = time.monotonic()
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=180,
    )
    duration = time.monotonic() - start
    resp.raise_for_status()
    raw = resp.json()["response"]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        s, e = raw.find("{"), raw.rfind("}") + 1
        try:
            parsed = json.loads(raw[s:e])
        except (json.JSONDecodeError, ValueError):
            parsed = {"incident_type": "PARSE_ERROR", "criticite": "basse",
                      "mitre_tactic": None, "mitre_technique": None}
    return parsed, duration


def criticality_gap(ref: str, predicted: str) -> int:
    try:
        return abs(CRITICALITY_ORDER.index(ref.lower()) - CRITICALITY_ORDER.index(predicted.lower()))
    except (ValueError, AttributeError):
        return len(CRITICALITY_ORDER)  # penalite max si valeur invalide


def mitre_match(ref_technique: str, predicted_technique) -> bool:
    if predicted_technique is None:
        return False
    if isinstance(predicted_technique, list):
        predicted_technique = " ".join(predicted_technique)
    predicted_technique = str(predicted_technique)
    return ref_technique in predicted_technique or predicted_technique in ref_technique


def main() -> None:
    with open(DATASET_FILE) as f:
        dataset = json.load(f)

    results = []
    for i, item in enumerate(dataset, 1):
        alert = item["alert"]
        ref = item["reference"]

        baseline = baseline_classify(alert)
        llm_result, llm_duration = llm_classify(alert)

        entry = {
            "scenario": item["scenario"],
            "reference": ref,
            "baseline": baseline,
            "llm": llm_result,
            "llm_duration_sec": round(llm_duration, 1),
            "baseline_criticality_gap": criticality_gap(ref["criticite"], baseline["criticite"]),
            "llm_criticality_gap": criticality_gap(ref["criticite"], llm_result.get("criticite", "")),
            "baseline_mitre_match": mitre_match(ref["mitre_technique"], baseline["mitre_technique"]),
            "llm_mitre_match": mitre_match(ref["mitre_technique"], llm_result.get("mitre_technique")),
        }
        results.append(entry)
        print(f"[{i}/{len(dataset)}] {item['scenario']}: "
              f"baseline_gap={entry['baseline_criticality_gap']} "
              f"llm_gap={entry['llm_criticality_gap']} "
              f"llm_mitre_match={entry['llm_mitre_match']} "
              f"({llm_duration:.1f}s)")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, default=str)

    n = len(results)
    avg_baseline_gap = sum(r["baseline_criticality_gap"] for r in results) / n
    avg_llm_gap = sum(r["llm_criticality_gap"] for r in results) / n
    baseline_mitre_rate = sum(r["baseline_mitre_match"] for r in results) / n
    llm_mitre_rate = sum(r["llm_mitre_match"] for r in results) / n
    avg_llm_time = sum(r["llm_duration_sec"] for r in results) / n

    print("\n===== RESUME METRIQUES =====")
    print(f"Nombre d'alertes evaluees        : {n}")
    print(f"Ecart moyen de criticite (regles) : {avg_baseline_gap:.2f}")
    print(f"Ecart moyen de criticite (LLM)     : {avg_llm_gap:.2f}")
    print(f"Taux de correspondance MITRE (regles) : {baseline_mitre_rate:.1%}")
    print(f"Taux de correspondance MITRE (LLM)     : {llm_mitre_rate:.1%}")
    print(f"Temps moyen de triage LLM          : {avg_llm_time:.1f}s")


if __name__ == "__main__":
    sys.exit(main())
