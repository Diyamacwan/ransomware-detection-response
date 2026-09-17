from datetime import datetime, timezone


class AlertGenerator:
    """Generate structured ransomware detection alerts."""

    def generate(self, result):
        """Create an alert from a detection result."""

        risk = result["risk"]
        detection = result["detection"]
        event = result["event"]

        # ML result
        ml = result.get("ml", {})

        ml_prediction = ml.get("prediction", 0)
        ml_probability = ml.get(
            "ransomware_probability",
            0.0
        )

        ml_classification = (
            "RANSOMWARE-LIKE"
            if ml_prediction == 1
            else "NORMAL"
        )

        # Combine rule-based and ML reasons.
        detection_reasons = list(
            detection.get("reasons", [])
        )

        if ml_prediction == 1:
            detection_reasons.append(
                "Machine-learning model classified "
                "the activity as ransomware-like"
            )

        alert = {
            "alert_id": self._generate_alert_id(),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "alert_type": "RANSOMWARE_SUSPECTED",

            "severity": risk["severity"],
            "risk_score": risk["risk_score"],

            "file_path": event["file_path"],
            "files_affected": result["files_in_window"],

            "detection_reasons": detection_reasons,

            # Machine-learning information
            "ml_prediction": ml_prediction,
            "ml_classification": ml_classification,
            "ml_probability": ml_probability,

            "recommended_action": self._recommended_action(
                risk["severity"]
            ),
        }

        return alert

    def _generate_alert_id(self):
        """Generate a unique alert ID."""

        timestamp = datetime.now(timezone.utc)

        return "ALERT-" + timestamp.strftime(
            "%Y%m%d-%H%M%S-%f"
        )

    def _recommended_action(self, severity):
        """Return the recommended defensive response."""

        if severity == "CRITICAL":
            return "IMMEDIATE INVESTIGATION AND CONTAINMENT"

        if severity == "HIGH":
            return "INVESTIGATE AND CONSIDER HOST CONTAINMENT"

        if severity == "MEDIUM":
            return "INVESTIGATE SUSPICIOUS FILE ACTIVITY"

        return "CONTINUE MONITORING"