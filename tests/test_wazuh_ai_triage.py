"""Tests unitaires pour scripts/wazuh_ai_triage.py -- ne touchent ni le reseau ni la VM,
uniquement les fonctions pures et la validation Pydantic."""
import os
import sqlite3
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-password-not-real")
os.environ.setdefault("THEHIVE_API_KEY", "test-key-not-real")

from wazuh_ai_triage import (  # noqa: E402
    TriageResult,
    already_processed,
    baseline_criticality,
    init_state_db,
    mark_processed,
)

# --- baseline_criticality ---

@pytest.mark.parametrize(
    "level,expected",
    [(0, "basse"), (4, "basse"), (5, "moyenne"), (8, "moyenne"), (9, "haute"), (11, "haute"), (12, "critique"), (20, "critique")],
)
def test_baseline_criticality(level, expected):
    assert baseline_criticality({"rule": {"level": level}}) == expected


def test_baseline_criticality_missing_level_defaults_to_basse():
    assert baseline_criticality({"rule": {}}) == "basse"
    assert baseline_criticality({}) == "basse"


# --- TriageResult schema ---

def _valid_payload(**overrides):
    payload = {
        "incident_type": "Brute force SSH",
        "criticite": "haute",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001",
        "resume": "Six tentatives sur des utilisateurs inexistants.",
        "recommandation": "Bloquer la source, verifier les autres tentatives.",
    }
    payload.update(overrides)
    return payload


def test_triage_result_accepts_valid_payload():
    result = TriageResult.model_validate(_valid_payload())
    assert result.mitre_technique == "T1110.001"
    assert result.criticite == "haute"


def test_triage_result_normalizes_english_criticality():
    result = TriageResult.model_validate(_valid_payload(criticite="high"))
    assert result.criticite == "haute"


def test_triage_result_rejects_invalid_criticality():
    with pytest.raises(ValidationError):
        TriageResult.model_validate(_valid_payload(criticite="urgent"))


def test_triage_result_rejects_malformed_mitre_code():
    with pytest.raises(ValidationError):
        TriageResult.model_validate(_valid_payload(mitre_technique="Phishing"))


def test_triage_result_rejects_missing_mitre_code():
    with pytest.raises(ValidationError):
        TriageResult.model_validate(_valid_payload(mitre_technique=""))


def test_triage_result_accepts_mitre_code_in_list_form():
    result = TriageResult.model_validate(_valid_payload(mitre_technique=["T1105"]))
    assert result.mitre_technique == "T1105"


def test_triage_result_rejects_prompt_injection_attempt_as_incident_type_too_long():
    # Le schema ne "comprend" pas le contenu, mais borne au moins sa taille --
    # une reponse anormalement longue (signe d'un modele qui a suivi des
    # instructions du log au lieu de classifier brievement) est rejetee.
    with pytest.raises(ValidationError):
        TriageResult.model_validate(_valid_payload(incident_type="A" * 500))


# --- idempotence (SQLite local, fichier temporaire) ---

def test_idempotence_marks_and_detects_processed_alert(tmp_path):
    db_path = str(tmp_path / "state.sqlite3")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS processed_alerts ("
        "  alert_id TEXT PRIMARY KEY, case_id TEXT, processed_at TEXT NOT NULL)"
    )
    conn.commit()

    assert already_processed(conn, "alert-123") is False
    mark_processed(conn, "alert-123", "case-456")
    assert already_processed(conn, "alert-123") is True
    assert already_processed(conn, "alert-999") is False
    conn.close()


def test_init_state_db_creates_table(tmp_path):
    os.environ["WAZUH_AI_TRIAGE_STATE_DB"] = str(tmp_path / "state.sqlite3")
    conn = init_state_db()
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='processed_alerts'")
    assert cursor.fetchone() is not None
    conn.close()
