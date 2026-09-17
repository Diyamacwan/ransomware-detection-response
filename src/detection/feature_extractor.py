from pathlib import Path

from src.detection.entropy_calculator import EntropyCalculator


class FeatureExtractor:
    """
    Extract measurable features from a filesystem event.

    This module only extracts features.
    It does not make detection or response decisions.
    """

    SUSPICIOUS_EXTENSIONS = {
        ".encrypted",
        ".locked",
        ".crypto",
        ".crypt",
        ".enc",
        ".wncry",
        ".wcry",
        ".locky",
        ".zepto",
    }

    def __init__(self):
        self.entropy_calculator = EntropyCalculator()

    def extract(self, event):
        """
        Extract features from a structured filesystem event.
        """

        file_path = Path(event["file_path"])
        file_name = event["file_name"]
        extension = event["file_extension"]
        event_type = event["event_type"]
        file_size = event["file_size"]

        entropy = self.entropy_calculator.calculate(file_path)

        is_suspicious_extension = (
            extension in self.SUSPICIOUS_EXTENSIONS
        )

        # ML feature:
        # 0 = normal extension
        # 1 = suspicious ransomware-style extension
        extension_risk = (
            1 if is_suspicious_extension else 0
        )

        features = {
            # Original event information
            "event_type": event_type,
            "file_size": file_size,
            "file_extension": extension,

            # File characteristics
            "file_name_length": len(file_name),
            "path_depth": len(file_path.parts),

            # Entropy
            "entropy": entropy,

            # Event indicators
            "is_created": event_type == "CREATED",
            "is_modified": event_type == "MODIFIED",
            "is_deleted": event_type == "DELETED",
            "is_moved": event_type == "MOVED",

            # Extension indicators
            "is_suspicious_extension": is_suspicious_extension,
            "extension_risk": extension_risk,
        }

        return features