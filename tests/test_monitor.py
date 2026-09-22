"""
Unit tests for the Ransomware Detection & Response System.

Run with:
    python -m pytest tests/ -v

Test classes
------------
  TestEntropyCalculator   (6 tests)
  TestFeatureExtractor    (7 tests)
  TestRansomwareDetector  (10 tests)
  TestRiskScorer          (9 tests)
  TestAlertGenerator      (9 tests)
  TestResponseEngine      (10 tests)
  TestBehaviorAnalyzer    (8 tests)
  TestMLPredictor         (6 tests)
  TestDashboardStore      (7 tests)
  TestRansomwareSimulator (5 tests)
"""

import json
import os
import tempfile
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────
# TestEntropyCalculator  (6 tests)
# ─────────────────────────────────────────────────────────────

class TestEntropyCalculator:

    def setup_method(self):
        from src.detection.entropy_calculator import EntropyCalculator
        self.calc = EntropyCalculator()

    def test_returns_zero_for_missing_file(self, tmp_path):
        result = self.calc.calculate(tmp_path / "nonexistent.txt")
        assert result == 0.0

    def test_returns_zero_for_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        assert self.calc.calculate(f) == 0.0

    def test_low_entropy_for_uniform_bytes(self, tmp_path):
        f = tmp_path / "uniform.bin"
        f.write_bytes(b"\x00" * 1024)
        assert self.calc.calculate(f) == 0.0

    def test_high_entropy_for_random_bytes(self, tmp_path):
        f = tmp_path / "random.bin"
        f.write_bytes(os.urandom(4096))
        result = self.calc.calculate(f)
        assert result > 7.0

    def test_medium_entropy_for_text(self, tmp_path):
        f = tmp_path / "text.txt"
        f.write_text("Hello world! This is a normal text file.", encoding="utf-8")
        result = self.calc.calculate(f)
        assert 2.0 < result < 6.0

    def test_result_is_float(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("abcdef", encoding="utf-8")
        assert isinstance(self.calc.calculate(f), float)


# ─────────────────────────────────────────────────────────────
# TestFeatureExtractor  (7 tests)
# ─────────────────────────────────────────────────────────────

class TestFeatureExtractor:

    def setup_method(self):
        from src.detection.feature_extractor import FeatureExtractor
        self.extractor = FeatureExtractor()

    def _make_event(self, tmp_path, extension=".txt", event_type="MODIFIED"):
        f = tmp_path / f"testfile{extension}"
        f.write_text("sample content", encoding="utf-8")
        return {
            "event_type": event_type,
            "file_path": str(f),
            "file_name": f.name,
            "file_extension": extension,
            "file_size": f.stat().st_size,
        }

    def test_extracts_all_expected_keys(self, tmp_path):
        event = self._make_event(tmp_path)
        features = self.extractor.extract(event)
        expected = [
            "event_type", "file_size", "file_extension",
            "file_name_length", "path_depth", "entropy",
            "is_created", "is_modified", "is_deleted", "is_moved",
            "is_suspicious_extension", "extension_risk",
        ]
        for key in expected:
            assert key in features, f"Missing key: {key}"

    def test_suspicious_extension_detected(self, tmp_path):
        event = self._make_event(tmp_path, extension=".locked")
        features = self.extractor.extract(event)
        assert features["is_suspicious_extension"] is True
        assert features["extension_risk"] == 1

    def test_normal_extension_not_flagged(self, tmp_path):
        event = self._make_event(tmp_path, extension=".txt")
        features = self.extractor.extract(event)
        assert features["is_suspicious_extension"] is False
        assert features["extension_risk"] == 0

    def test_event_type_flags(self, tmp_path):
        for etype, flag in [
            ("CREATED", "is_created"),
            ("MODIFIED", "is_modified"),
            ("DELETED", "is_deleted"),
            ("MOVED", "is_moved"),
        ]:
            event = self._make_event(tmp_path, event_type=etype)
            features = self.extractor.extract(event)
            assert features[flag] is True

    def test_all_suspicious_extensions_flagged(self, tmp_path):
        """Every extension in the known set should be flagged."""
        from src.detection.feature_extractor import FeatureExtractor
        known = FeatureExtractor.SUSPICIOUS_EXTENSIONS
        for ext in known:
            event = self._make_event(tmp_path, extension=ext)
            features = self.extractor.extract(event)
            assert features["is_suspicious_extension"] is True, f"{ext} not flagged"

    def test_file_name_length_is_correct(self, tmp_path):
        event = self._make_event(tmp_path, extension=".txt")
        features = self.extractor.extract(event)
        assert features["file_name_length"] == len("testfile.txt")

    def test_path_depth_is_positive(self, tmp_path):
        event = self._make_event(tmp_path, extension=".txt")
        features = self.extractor.extract(event)
        assert features["path_depth"] > 0


# ─────────────────────────────────────────────────────────────
# TestRansomwareDetector  (10 tests)
# ─────────────────────────────────────────────────────────────

class TestRansomwareDetector:

    def setup_method(self):
        from src.detection.ransomware_detector import RansomwareDetector
        self.detector = RansomwareDetector()

    def _features(self, entropy=3.0, suspicious_ext=False):
        return {
            "entropy": entropy,
            "is_suspicious_extension": suspicious_ext,
        }

    def test_no_rules_triggered_for_normal_activity(self):
        result = self.detector.detect(self._features(), files_in_window=2)
        assert result["suspicious"] is False
        assert result["rules_triggered"] == []

    def test_suspicious_extension_rule_triggers(self):
        result = self.detector.detect(
            self._features(suspicious_ext=True), files_in_window=0
        )
        assert "SUSPICIOUS_EXTENSION" in result["rules_triggered"]
        assert result["suspicious"] is True

    def test_high_entropy_rule_triggers(self):
        result = self.detector.detect(
            self._features(entropy=7.5), files_in_window=0
        )
        assert "HIGH_ENTROPY" in result["rules_triggered"]
        assert result["suspicious"] is True

    def test_modest_bulk_activity_does_not_trigger_mass_modification(self):
        result = self.detector.detect(
            self._features(), files_in_window=10
        )
        assert "MASS_MODIFICATION" not in result["rules_triggered"]
        assert result["suspicious"] is False

    def test_mass_modification_rule_triggers(self):
        result = self.detector.detect(
            self._features(), files_in_window=15
        )
        assert "MASS_MODIFICATION" in result["rules_triggered"]
        assert result["suspicious"] is True

    def test_all_three_rules_trigger_together(self):
        result = self.detector.detect(
            self._features(entropy=7.5, suspicious_ext=True),
            files_in_window=15,
        )
        assert len(result["rules_triggered"]) == 3
        assert result["suspicious"] is True

    def test_entropy_exactly_at_threshold_triggers(self):
        result = self.detector.detect(
            self._features(entropy=7.0), files_in_window=0
        )
        assert "HIGH_ENTROPY" in result["rules_triggered"]

    def test_entropy_below_threshold_does_not_trigger(self):
        result = self.detector.detect(
            self._features(entropy=6.99), files_in_window=0
        )
        assert "HIGH_ENTROPY" not in result["rules_triggered"]

    def test_result_contains_reasons_for_each_triggered_rule(self):
        result = self.detector.detect(
            self._features(entropy=7.5, suspicious_ext=True), files_in_window=0
        )
        assert len(result["reasons"]) >= 2

    def test_result_includes_files_in_window(self):
        result = self.detector.detect(self._features(), files_in_window=5)
        assert result["files_in_window"] == 5


# ─────────────────────────────────────────────────────────────
# TestRiskScorer  (9 tests)
# ─────────────────────────────────────────────────────────────

class TestRiskScorer:

    def setup_method(self):
        from src.detection.risk_scorer import RiskScorer
        self.scorer = RiskScorer()

    def _detection(self, rules):
        return {"rules_triggered": rules}

    def test_zero_score_for_no_rules(self):
        result = self.scorer.score(self._detection([]))
        assert result["risk_score"] == 0
        assert result["severity"] == "LOW"

    def test_mass_modification_adds_40(self):
        result = self.scorer.score(self._detection(["MASS_MODIFICATION"]))
        assert result["risk_score"] == 40
        assert result["severity"] == "MEDIUM"

    def test_high_entropy_adds_30(self):
        result = self.scorer.score(self._detection(["HIGH_ENTROPY"]))
        assert result["risk_score"] == 30
        assert result["severity"] == "MEDIUM"

    def test_suspicious_extension_adds_30(self):
        result = self.scorer.score(self._detection(["SUSPICIOUS_EXTENSION"]))
        assert result["risk_score"] == 30
        assert result["severity"] == "MEDIUM"

    def test_all_rules_gives_100(self):
        result = self.scorer.score(
            self._detection(
                ["MASS_MODIFICATION", "HIGH_ENTROPY", "SUSPICIOUS_EXTENSION"]
            )
        )
        assert result["risk_score"] == 100
        assert result["severity"] == "CRITICAL"

    def test_severity_high_at_70(self):
        result = self.scorer.score(
            self._detection(["MASS_MODIFICATION", "HIGH_ENTROPY"])
        )
        assert result["severity"] == "HIGH"

    def test_score_does_not_exceed_100(self):
        result = self.scorer.score(
            self._detection(
                ["MASS_MODIFICATION", "HIGH_ENTROPY", "SUSPICIOUS_EXTENSION"]
            )
        )
        assert result["risk_score"] <= 100

    def test_get_severity_boundary_critical(self):
        assert self.scorer.get_severity(80) == "CRITICAL"
        assert self.scorer.get_severity(100) == "CRITICAL"

    def test_get_severity_boundary_low(self):
        assert self.scorer.get_severity(0) == "LOW"
        assert self.scorer.get_severity(29) == "LOW"


# ─────────────────────────────────────────────────────────────
# TestAlertGenerator  (9 tests)
# ─────────────────────────────────────────────────────────────

class TestAlertGenerator:

    def setup_method(self):
        from src.response.alert_generator import AlertGenerator
        self.generator = AlertGenerator()

    def _make_result(self, severity="MEDIUM", risk_score=40, ml_prediction=0):
        return {
            "risk": {"severity": severity, "risk_score": risk_score},
            "detection": {"reasons": ["Test reason"], "rules_triggered": []},
            "event": {
                "file_path": "/test/file.txt",
                "event_type": "MODIFIED",
            },
            "ml": {
                "prediction": ml_prediction,
                "ransomware_probability": 0.85 if ml_prediction else 0.1,
            },
            "files_in_window": 5,
        }

    def test_alert_contains_required_fields(self):
        alert = self.generator.generate(self._make_result())
        for field in [
            "alert_id", "timestamp", "alert_type", "severity",
            "risk_score", "file_path", "files_affected",
            "detection_reasons", "ml_classification", "ml_probability",
            "recommended_action",
        ]:
            assert field in alert, f"Missing field: {field}"

    def test_alert_id_starts_with_prefix(self):
        alert = self.generator.generate(self._make_result())
        assert alert["alert_id"].startswith("ALERT-")

    def test_ml_classification_ransomware_when_prediction_1(self):
        alert = self.generator.generate(self._make_result(ml_prediction=1))
        assert alert["ml_classification"] == "RANSOMWARE-LIKE"

    def test_ml_classification_normal_when_prediction_0(self):
        alert = self.generator.generate(self._make_result(ml_prediction=0))
        assert alert["ml_classification"] == "NORMAL"

    def test_recommended_action_critical(self):
        alert = self.generator.generate(self._make_result(severity="CRITICAL"))
        assert "CONTAINMENT" in alert["recommended_action"]

    def test_recommended_action_high(self):
        alert = self.generator.generate(self._make_result(severity="HIGH"))
        assert "CONTAINMENT" in alert["recommended_action"]

    def test_recommended_action_medium(self):
        alert = self.generator.generate(self._make_result(severity="MEDIUM"))
        assert "INVESTIGATE" in alert["recommended_action"]

    def test_alert_type_is_ransomware_suspected(self):
        alert = self.generator.generate(self._make_result())
        assert alert["alert_type"] == "RANSOMWARE_SUSPECTED"

    def test_files_affected_matches_result(self):
        alert = self.generator.generate(self._make_result())
        assert alert["files_affected"] == 5


# ─────────────────────────────────────────────────────────────
# TestResponseEngine  (10 tests)
# ─────────────────────────────────────────────────────────────

class TestResponseEngine:

    def _make_alert(self, severity="MEDIUM", risk_score=40):
        return {
            "alert_id": "ALERT-TEST-001",
            "severity": severity,
            "file_path": "/test/file.txt",
            "risk_score": risk_score,
        }

    def test_response_written_to_log(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        alert = self._make_alert()
        response = engine.respond(alert)
        assert engine.RESPONSE_LOG.exists()
        with open(engine.RESPONSE_LOG, encoding="utf-8") as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["response_id"] == response["response_id"]

    def test_critical_severity_maps_to_containment(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert(severity="CRITICAL"))
        assert response["action"] == "HOST_CONTAINMENT_RECOMMENDED"

    def test_high_severity_maps_to_isolation(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert(severity="HIGH"))
        assert response["action"] == "HOST_ISOLATION_RECOMMENDED"

    def test_medium_severity_maps_to_review(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert(severity="MEDIUM"))
        assert response["action"] == "SUSPICIOUS_ACTIVITY_REVIEW"

    def test_low_severity_maps_to_monitoring(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert(severity="LOW"))
        assert response["action"] == "CONTINUE_MONITORING"

    def test_response_id_starts_with_prefix(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert())
        assert response["response_id"].startswith("RESP-")

    def test_status_is_simulated(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert())
        assert response["status"] == "SIMULATED"

    def test_multiple_responses_appended_to_log(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        engine.respond(self._make_alert())
        engine.respond(self._make_alert())
        with open(engine.RESPONSE_LOG, encoding="utf-8") as f:
            data = json.load(f)
        assert len(data) == 2

    def test_response_contains_file_path(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert())
        assert response["file_path"] == "/test/file.txt"

    def test_response_contains_risk_score(self, tmp_path):
        from src.response.response_engine import ResponseEngine
        engine = ResponseEngine()
        engine.RESPONSE_LOG = tmp_path / "test_response_log.json"
        response = engine.respond(self._make_alert(risk_score=70))
        assert response["risk_score"] == 70


# ─────────────────────────────────────────────────────────────
# TestBehaviorAnalyzer  (8 tests)
# ─────────────────────────────────────────────────────────────

class TestBehaviorAnalyzer:

    def _make_event(self, tmp_path, event_type="MODIFIED", extension=".txt", file_size=1000):
        f = tmp_path / f"testfile{extension}"
        f.write_text("sample", encoding="utf-8")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "file_path": str(f),
            "file_name": f.name,
            "file_extension": extension,
            "file_size": file_size,
        }

    def test_analyze_returns_required_keys(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        event = self._make_event(tmp_path)
        result = analyzer.analyze(event)
        for key in ["suspicious", "event", "features", "detection", "ml", "risk",
                    "files_in_window", "modification_rate"]:
            assert key in result, f"Missing key: {key}"

    def test_non_modified_event_has_zero_window(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        event = self._make_event(tmp_path, event_type="CREATED")
        result = analyzer.analyze(event)
        assert result["files_in_window"] == 0
        assert result["modification_rate"] == 0.0

    def test_modified_events_accumulate_in_window(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer(window_seconds=10)
        for i in range(5):
            f = tmp_path / f"file_{i}.txt"
            f.write_text("data", encoding="utf-8")
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "MODIFIED",
                "file_path": str(f),
                "file_name": f.name,
                "file_extension": ".txt",
                "file_size": 10,
            }
            result = analyzer.analyze(event)
        assert result["files_in_window"] == 5

    def test_suspicious_extension_marks_result_suspicious(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        event = self._make_event(tmp_path, extension=".locked")
        result = analyzer.analyze(event)
        assert result["suspicious"] is True

    def test_risk_dict_has_score_and_severity(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        result = analyzer.analyze(self._make_event(tmp_path))
        assert "risk_score" in result["risk"]
        assert "severity" in result["risk"]

    def test_ml_result_has_required_fields(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        result = analyzer.analyze(self._make_event(tmp_path))
        assert "prediction" in result["ml"]
        assert "ransomware_probability" in result["ml"]
        assert "is_ransomware" in result["ml"]

    def test_modification_rate_is_non_negative(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        result = analyzer.analyze(self._make_event(tmp_path))
        assert result["modification_rate"] >= 0.0

    def test_deletion_event_does_not_raise(self, tmp_path):
        from src.detection.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        event = self._make_event(tmp_path, event_type="DELETED")
        # File may or may not exist — must not raise
        result = analyzer.analyze(event)
        assert "suspicious" in result


# ─────────────────────────────────────────────────────────────
# TestMLPredictor  (6 tests)
# ─────────────────────────────────────────────────────────────

class TestMLPredictor:

    def setup_method(self):
        from src.detection.ml_predictor import MLPredictor
        self.predictor = MLPredictor()

    def _features(self, file_size=100000, entropy=3.5, files_in_window=2,
                  extension_risk=0, modification_rate=0.5):
        return {
            "file_size": file_size,
            "entropy": entropy,
            "files_in_window": files_in_window,
            "extension_risk": extension_risk,
            "modification_rate": modification_rate,
        }

    def test_predict_returns_required_keys(self):
        result = self.predictor.predict(self._features())
        assert "prediction" in result
        assert "ransomware_probability" in result
        assert "is_ransomware" in result

    def test_prediction_is_0_or_1(self):
        result = self.predictor.predict(self._features())
        assert result["prediction"] in (0, 1)

    def test_probability_is_between_0_and_1(self):
        result = self.predictor.predict(self._features())
        assert 0.0 <= result["ransomware_probability"] <= 1.0

    def test_normal_features_predict_not_ransomware(self):
        result = self.predictor.predict(self._features(
            entropy=2.5, files_in_window=1, extension_risk=0, modification_rate=0.1
        ))
        assert result["ransomware_probability"] < 0.5

    def test_ransomware_features_predict_ransomware(self):
        result = self.predictor.predict(self._features(
            entropy=7.8, files_in_window=40, extension_risk=1, modification_rate=25.0
        ))
        assert result["ransomware_probability"] > 0.5

    def test_is_ransomware_matches_prediction(self):
        result = self.predictor.predict(self._features())
        assert result["is_ransomware"] == (result["prediction"] == 1)


# ─────────────────────────────────────────────────────────────
# TestDashboardStore  (7 tests)
# ─────────────────────────────────────────────────────────────

class TestDashboardStore:

    def setup_method(self):
        from src.dashboard.store import _RingBuffer
        self.store = _RingBuffer(maxlen=5)

    def test_push_increments_count(self):
        self.store.push({"id": 1})
        assert self.store.count() == 1

    def test_all_returns_all_items(self):
        self.store.push({"id": 1})
        self.store.push({"id": 2})
        items = self.store.all()
        assert len(items) == 2

    def test_maxlen_respected(self):
        for i in range(10):
            self.store.push({"id": i})
        assert self.store.count() == 5

    def test_oldest_dropped_when_full(self):
        for i in range(10):
            self.store.push({"id": i})
        ids = [item["id"] for item in self.store.all()]
        assert ids == [5, 6, 7, 8, 9]

    def test_since_returns_last_n(self):
        for i in range(5):
            self.store.push({"id": i})
        result = self.store.since(2)
        assert len(result) == 2
        assert result[-1]["id"] == 4

    def test_subscribe_receives_push(self):
        q = self.store.subscribe()
        self.store.push({"val": "test"})
        item = q.get(timeout=1)
        assert item["val"] == "test"

    def test_unsubscribe_stops_delivery(self):
        import queue as _queue
        q = self.store.subscribe()
        self.store.unsubscribe(q)
        self.store.push({"val": "after_unsub"})
        with pytest.raises(_queue.Empty):
            q.get_nowait()


# ─────────────────────────────────────────────────────────────
# TestRansomwareSimulator  (5 tests)
# ─────────────────────────────────────────────────────────────

class TestRansomwareSimulator:
    """Test the simulation functions in isolation (no monitor needed)."""

    def test_create_test_files_creates_directory(self, tmp_path, monkeypatch):
        from src.simulation import ransomware_simulator as sim
        monkeypatch.setattr(sim, "SIMULATION_DIRECTORY", tmp_path / "sim")
        sim.create_test_files()
        assert (tmp_path / "sim").exists()

    def test_create_test_files_creates_correct_count(self, tmp_path, monkeypatch):
        from src.simulation import ransomware_simulator as sim
        monkeypatch.setattr(sim, "SIMULATION_DIRECTORY", tmp_path / "sim")
        sim.create_test_files()
        txt_files = list((tmp_path / "sim").glob("document_*.txt"))
        assert len(txt_files) == sim.NORMAL_FILE_COUNT

    def test_suspicious_extensions_creates_files(self, tmp_path, monkeypatch):
        from src.simulation import ransomware_simulator as sim
        monkeypatch.setattr(sim, "SIMULATION_DIRECTORY", tmp_path / "sim")
        (tmp_path / "sim").mkdir()
        sim.simulate_suspicious_extensions()
        suspicious = list((tmp_path / "sim").iterdir())
        assert len(suspicious) == sim.ENCRYPTED_EXT_COUNT

    def test_high_entropy_files_have_near_max_entropy(self, tmp_path, monkeypatch):
        from src.simulation import ransomware_simulator as sim
        from src.detection.entropy_calculator import EntropyCalculator
        monkeypatch.setattr(sim, "SIMULATION_DIRECTORY", tmp_path / "sim")
        (tmp_path / "sim").mkdir()
        sim.simulate_high_entropy()
        calc = EntropyCalculator()
        enc_files = list((tmp_path / "sim").glob("*.enc"))
        assert len(enc_files) == 5
        for f in enc_files:
            assert calc.calculate(f) > 7.0, f"{f.name} entropy not high enough"

    def test_ransom_note_contains_bitcoin(self, tmp_path, monkeypatch):
        from src.simulation import ransomware_simulator as sim
        monkeypatch.setattr(sim, "SIMULATION_DIRECTORY", tmp_path / "sim")
        (tmp_path / "sim").mkdir()
        sim.drop_ransom_note()
        notes = list((tmp_path / "sim").glob("*.txt")) + list((tmp_path / "sim").glob("*.html"))
        assert len(notes) >= 1
        for note in notes:
            content = note.read_text(encoding="utf-8").lower()
            assert "bitcoin" in content or "decrypt" in content
