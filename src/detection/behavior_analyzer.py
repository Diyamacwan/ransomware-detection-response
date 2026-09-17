from collections import deque
from datetime import datetime, timedelta

from src.detection.feature_extractor import FeatureExtractor
from src.detection.ransomware_detector import RansomwareDetector
from src.detection.risk_scorer import RiskScorer
from src.detection.ml_predictor import MLPredictor


class BehaviorAnalyzer:
    """
    Analyze filesystem events using both rule-based
    detection and machine-learning prediction.
    """

    def __init__(self, window_seconds=10, modification_threshold=10):
        self.window_seconds = window_seconds
        self.modification_threshold = modification_threshold

        self.modification_events = deque()

        self.feature_extractor = FeatureExtractor()
        self.ransomware_detector = RansomwareDetector()
        self.risk_scorer = RiskScorer()
        self.ml_predictor = MLPredictor()

    def analyze(self, event):
        """
        Analyze a single filesystem event.
        """

        # ---------------------------------------------------------
        # Extract basic file features
        # ---------------------------------------------------------

        features = self.feature_extractor.extract(event)

        # ---------------------------------------------------------
        # Non-MODIFIED events
        # ---------------------------------------------------------

        if event["event_type"] != "MODIFIED":

            files_in_window = 0
            modification_rate = 0.0

            features["files_in_window"] = files_in_window
            features["modification_rate"] = modification_rate

            detection = self.ransomware_detector.detect(
                features,
                files_in_window
            )

            ml_result = self.ml_predictor.predict(
                features
            )

            risk = self.risk_scorer.score(detection)

            # ML prediction can also indicate suspicious behavior.
            ml_suspicious = ml_result["is_ransomware"]

            suspicious = (
                detection["suspicious"]
                or ml_suspicious
            )

            reasons = list(
                detection["reasons"]
            )

            if ml_suspicious:
                reasons.append(
                    "Machine-learning model classified "
                    "the activity as ransomware-like"
                )

            return {
                "suspicious": suspicious,
                "reason": "; ".join(reasons)
                if reasons
                else None,
                "event": event,
                "features": features,
                "detection": detection,
                "ml": ml_result,
                "risk": risk,
                "files_in_window": files_in_window,
                "modification_rate": modification_rate,
            }

        # ---------------------------------------------------------
        # MODIFIED events
        # ---------------------------------------------------------

        timestamp = datetime.fromisoformat(
            event["timestamp"]
        )

        self.modification_events.append(
            {
                "timestamp": timestamp,
                "file_path": event["file_path"],
            }
        )

        cutoff_time = timestamp - timedelta(
            seconds=self.window_seconds
        )

        # Remove old modification events.
        while (
            self.modification_events
            and self.modification_events[0]["timestamp"]
            < cutoff_time
        ):
            self.modification_events.popleft()

        # Count unique files modified in the time window.
        unique_files = {
            item["file_path"]
            for item in self.modification_events
        }

        files_in_window = len(unique_files)

        # Calculate modification rate.
        modification_count = len(
            self.modification_events
        )

        modification_rate = round(
            modification_count / self.window_seconds,
            2
        )

        # Add ML features.
        features["files_in_window"] = files_in_window
        features["modification_rate"] = modification_rate

        # ---------------------------------------------------------
        # Rule-based detection
        # ---------------------------------------------------------

        detection = self.ransomware_detector.detect(
            features,
            files_in_window
        )

        # ---------------------------------------------------------
        # Machine-learning prediction
        # ---------------------------------------------------------

        ml_result = self.ml_predictor.predict(
            features
        )

        # ---------------------------------------------------------
        # Combined decision
        # ---------------------------------------------------------

        ml_suspicious = ml_result["is_ransomware"]

        suspicious = (
            detection["suspicious"]
            or ml_suspicious
        )

        reasons = list(
            detection["reasons"]
        )

        if ml_suspicious:
            reasons.append(
                "Machine-learning model classified "
                "the activity as ransomware-like"
            )

        # ---------------------------------------------------------
        # Risk scoring
        # ---------------------------------------------------------

        risk = self.risk_scorer.score(
            detection
        )

        # Add ML contribution to risk score.
        if ml_suspicious:
            risk["risk_score"] = max(
                risk["risk_score"],
                70
            )

            if risk["risk_score"] >= 80:
                risk["severity"] = "CRITICAL"
            else:
                risk["severity"] = "HIGH"

        return {
            "suspicious": suspicious,
            "reason": "; ".join(reasons)
            if reasons
            else None,
            "event": event,
            "features": features,
            "detection": detection,
            "ml": ml_result,
            "risk": risk,
            "files_in_window": files_in_window,
            "modification_rate": modification_rate,
        }