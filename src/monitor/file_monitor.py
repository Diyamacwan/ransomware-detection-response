from datetime import datetime, timezone
from pathlib import Path
import traceback

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.detection.behavior_analyzer import BehaviorAnalyzer
from src.response.alert_generator import AlertGenerator
from src.response.response_engine import ResponseEngine
from src.utils.logger import get_logger

logger = get_logger("ransomware.monitor")


class FileMonitorHandler(FileSystemEventHandler):
    """Handle filesystem events and generate ransomware alerts."""

    def __init__(self):
        super().__init__()

        self.analyzer = BehaviorAnalyzer()
        self.alert_generator = AlertGenerator()
        self.response_engine = ResponseEngine()

        # Prevent repeated alerts during the same suspicious activity burst.
        self.alert_active = False

        # Track the last time suspicious activity was observed.
        self.last_suspicious_time = None

        # Number of seconds after which a new suspicious activity
        # period can generate another alert.
        self.alert_reset_seconds = 10

    def _create_event(self, event_type, file_path):
        """Create a structured filesystem event."""

        path = Path(file_path)

        try:
            file_size = path.stat().st_size if path.exists() else 0
        except OSError:
            file_size = 0

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "file_path": str(path.resolve()),
            "file_name": path.name,
            "file_extension": path.suffix.lower(),
            "file_size": file_size,
        }

    def _reset_alert_if_activity_expired(self):
        """Reset alert state after the suspicious activity period ends."""

        if self.last_suspicious_time is None:
            return

        elapsed = (
            datetime.now(timezone.utc)
            - self.last_suspicious_time
        ).total_seconds()

        if elapsed >= self.alert_reset_seconds:
            self.alert_active = False
            self.last_suspicious_time = None

    def _print_event(self, event):
        """Analyze event and generate an alert when necessary."""

        try:
            # Check whether the previous suspicious activity period
            # has expired.
            self._reset_alert_if_activity_expired()

            result = self.analyzer.analyze(event)

            features = result["features"]
            risk = result["risk"]
            ml = result.get("ml", {})

            ml_prediction = ml.get("prediction", 0)
            ml_probability = ml.get("ransomware_probability", 0.0)

            logger.info(
                "[%s] %s | size=%s bytes | extension=%s | "
                "entropy=%s | files_in_window=%s | "
                "modification_rate=%s | ML=%s | "
                "ML_probability=%.2f%% | risk=%s | severity=%s",
                event["event_type"],
                event["file_path"],
                event["file_size"],
                event["file_extension"],
                features["entropy"],
                result["files_in_window"],
                result["modification_rate"],
                ml_prediction,
                ml_probability * 100,
                risk["risk_score"],
                risk["severity"],
            )

            if result["suspicious"]:

                # Record the time of the latest suspicious event.
                self.last_suspicious_time = datetime.now(timezone.utc)

                # Generate only one alert for the current
                # suspicious activity burst.
                if not self.alert_active:

                    alert = self.alert_generator.generate(result)
                    self._log_alert(alert)

                    # Execute the safe defensive response.
                    response = self.response_engine.respond(alert)
                    self._log_response(response)

                    self.alert_active = True

        except Exception:
            logger.error("[!!! ERROR INSIDE EVENT HANDLER !!!]")
            logger.debug(traceback.format_exc())

    def _log_alert(self, alert):
        """Log a structured ransomware alert."""

        logger.warning("=" * 60)
        logger.warning("           RANSOMWARE ALERT")
        logger.warning("=" * 60)
        logger.warning("Alert ID          : %s", alert["alert_id"])
        logger.warning("Alert Type        : %s", alert["alert_type"])
        logger.warning("Severity          : %s", alert["severity"])
        logger.warning("Risk Score        : %s/100", alert["risk_score"])
        logger.warning("ML Classification : %s", alert["ml_classification"])
        logger.warning(
            "ML Probability    : %.2f%%",
            alert["ml_probability"] * 100,
        )
        logger.warning("File              : %s", alert["file_path"])
        logger.warning("Files Affected    : %s", alert["files_affected"])
        logger.warning(
            "Reason            : %s",
            "; ".join(alert["detection_reasons"]),
        )
        logger.warning(
            "Recommended       : %s", alert["recommended_action"]
        )
        logger.warning("Timestamp         : %s", alert["timestamp"])
        logger.warning("=" * 60)

    def _log_response(self, response):
        """Log the defensive response action."""

        logger.info("[+] RESPONSE ACTION")
        logger.info("Response ID : %s", response["response_id"])
        logger.info("Action      : %s", response["action"])
        logger.info("Status      : %s", response["status"])
        logger.info("Log File    : %s", self.response_engine.RESPONSE_LOG)
        logger.info("[+] Response recorded successfully.")

    def on_created(self, event):
        """Handle file creation."""

        if not event.is_directory:
            file_event = self._create_event("CREATED", event.src_path)
            self._print_event(file_event)

    def on_modified(self, event):
        """Handle file modification."""

        if not event.is_directory:
            file_event = self._create_event("MODIFIED", event.src_path)
            self._print_event(file_event)

    def on_deleted(self, event):
        """Handle file deletion."""

        if not event.is_directory:
            file_event = self._create_event("DELETED", event.src_path)
            self._print_event(file_event)

    def on_moved(self, event):
        """Handle file move/rename."""

        if not event.is_directory:
            file_event = self._create_event("MOVED", event.dest_path)
            self._print_event(file_event)


def start_monitor(directory: str):
    """Start monitoring a directory."""

    path = Path(directory).resolve()

    if not path.exists():
        raise FileNotFoundError(
            f"Directory does not exist: {path}"
        )

    logger.info("[+] Monitoring: %s", path)
    logger.info("[+] Press Ctrl+C to stop.")

    event_handler = FileMonitorHandler()

    observer = Observer()

    observer.schedule(
        event_handler,
        str(path),
        recursive=True,
    )

    observer.start()

    try:
        while True:
            observer.join(1)

    except KeyboardInterrupt:
        logger.info("[!] Stopping monitor...")
        observer.stop()

    observer.join()
    logger.info("[+] Monitor stopped.")


if __name__ == "__main__":
    start_monitor("test_data")
