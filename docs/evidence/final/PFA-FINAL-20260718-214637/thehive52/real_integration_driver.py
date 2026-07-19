"""Test d'integration reel du pipeline complet (fetch -> triage LLM -> creation de cas
TheHive 5.2.16-1 en mode THEHIVE_DEDUP_MODE=tag) pour le RUN_ID PFA-FINAL-20260718-214637.
Utilise l'alerte reelle 9em5ep8B-jsqxPD_sgRy (regle 100103, generee par une commande
reelle executee sur cette VM juste avant ce test), pas une alerte fabriquee. Toutes les
sorties (requete/reponse LLM brute, reponse TheHive brute, case_id, tag) sont ecrites sur
stdout en JSON pour etre capturees telles quelles comme preuve."""
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~"))
os.environ["THEHIVE_URL"] = "http://127.0.0.1:9020"
os.environ["THEHIVE_API_KEY"] = os.environ["THEHIVE_API_KEY"]  # fourni par l'environnement, jamais en dur (cle reelle utilisee lors de l'execution : voir CREDENTIALS.md local, hors depot)
os.environ["THEHIVE_DEDUP_MODE"] = "tag"
os.environ["THEHIVE_ORGANISATION"] = "soc-lab"
os.environ["WAZUH_INDEXER_PASSWORD"] = "placeholder-not-used-by-this-driver"

import wazuh_ai_triage as wat

ALERT_ES_ID = "9em5ep8B-jsqxPD_sgRy"

with open(os.path.expanduser("~/real_alert_for_integration_test.json")) as f:
    hit = json.load(f)
alert = hit["_source"]
alert["_es_id"] = hit["_id"]
assert alert["_es_id"] == ALERT_ES_ID

out = {"alert_es_id": alert["_es_id"], "rule_id": alert.get("rule", {}).get("id")}

print("=== ETAPE 1 : triage LLM reel (Ollama/Gemma2) ===", file=sys.stderr)
triage = wat.triage_with_llm(alert)
if triage is None:
    out["triage"] = None
    print(json.dumps(out, indent=2))
    sys.exit(1)
out["triage"] = triage.model_dump()

criticite = wat.baseline_criticality(alert)
out["criticite_baseline"] = criticite

print("=== ETAPE 2 : create_thehive_case (mode=tag), run 1 (creation attendue) ===", file=sys.stderr)
result1 = wat.create_thehive_case(alert, triage, criticite)
out["run1_result"] = result1
out["deterministic_tag"] = wat.build_source_ref_tag(alert["_es_id"])

print("=== ETAPE 3 : GET case cree pour verifier le tag persiste ===", file=sys.stderr)
import requests
resp = requests.get(
    f"{wat.THEHIVE_URL}/api/v1/case/{result1['case_id']}",
    headers=wat._thehive_headers(),
    timeout=15,
)
out["run1_case_get"] = resp.json()

print("=== ETAPE 4 : rerun create_thehive_case avec la MEME alerte (etat SQLite absent, "
      "simule via l'absence totale d'appel a init_state_db/already_processed) ===", file=sys.stderr)
result2 = wat.create_thehive_case(alert, triage, criticite)
out["run2_result"] = result2
out["no_duplicate"] = (result1["case_id"] == result2["case_id"]) and (result2["created"] is False)

print(json.dumps(out, indent=2))
