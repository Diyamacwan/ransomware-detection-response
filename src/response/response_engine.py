from datetime import datetime, timezone
from pathlib import Path
import json


class ResponseEngine:
    """
    Defensive response engine for ransomware alerts.

    This module does not delete, encrypt, or modify user files.
    It records recommended response actions and can safely
    simulate containment for testing and demonstration.
    """

    RESPONSE_LOG = Path("logs/response_log.json")

    def __init__(self):
        self.RESPONSE_LOG.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def respond(self, alert):
        """
        Execute a safe defensive response based on alert severity.
        """

        severity = alert.get("severity", "LOW")

        if severity == "CRITICAL":
            action = "HOST_CONTAINMENT_RECOMMENDED"

        elif severity == "HIGH":
            action = "HOST_ISOLATION_RECOMMENDED"

        elif severity == "MEDIUM":
            action = "SUSPICIOUS_ACTIVITY_REVIEW"

        else:
            action = "CONTINUE_MONITORING"

        response = {
            "response_id": self._generate_response_id(),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "alert_id": alert.get("alert_id"),
            "severity": severity,
            "action": action,
            "status": "SIMULATED",
            "file_path": alert.get("file_path"),
            "risk_score": alert.get("risk_score"),
        }

        self._log_response(response)

        return response

    def _generate_response_id(self):
        """Generate a unique response ID."""

        timestamp = datetime.now(timezone.utc)

        return "RESP-" + timestamp.strftime(
            "%Y%m%d-%H%M%S-%f"
        )

    def _log_response(self, response):
        """Store response information in a JSON log."""

        existing_responses = []

        if self.RESPONSE_LOG.exists():

            try:
                with open(
                    self.RESPONSE_LOG,
                    "r",
                    encoding="utf-8"
                ) as file:

                    existing_responses = json.load(file)

                    if not isinstance(
                        existing_responses,
                        list
                    ):
                        existing_responses = []

            except (json.JSONDecodeError, OSError):
                existing_responses = []

        existing_responses.append(response)

        with open(
            self.RESPONSE_LOG,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                existing_responses,
                file,
                indent=4
            )