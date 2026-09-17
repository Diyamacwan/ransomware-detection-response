"""
Unit tests for the Ransomware Detection & Response System.

Run with:
    python -m pytest tests/ -v
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────
# EntropyCalculator
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
        import os
        f = tmp_path / "random.bin"
        f.write_bytes(os.urandom(4096))
        result = self.calc.calculate(f)
        # Random bytes should produce entropy close to 8
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
# FeatureExtractor
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


# ─────────────────────────────────────────────────────────────
# RansomwareDetector
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


# ─────────────────────────────────────────────────────────────
# RiskScorer
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

    def test_severity_high_at_60(self):
        # MASS_MODIFICATION(40) + HIGH_ENTROPY(30) = 70 → HIGH
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


# ─────────────────────────────────────────────────────────────
# AlertGenerator
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


# ─────────────────────────────────────────────────────────────
# ResponseEngine
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
