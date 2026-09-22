class RansomwareDetector:
    """
    Defensive rule-based ransomware behavior detector.

    This detector only analyzes filesystem activity.
    It does not modify, encrypt, delete, or execute files.
    """

    HIGH_ENTROPY_THRESHOLD = 7.0
    MASS_MODIFICATION_THRESHOLD = 12
    MODERATE_MODIFICATION_THRESHOLD = 10

    def detect(self, features, files_in_window=0):
        """
        Evaluate filesystem features against ransomware-related rules.
        """

        rules_triggered = []
        reasons = []

        # Rule 1: Suspicious extension
        if features.get("is_suspicious_extension", False):
            rules_triggered.append("SUSPICIOUS_EXTENSION")

            reasons.append(
                "Suspicious ransomware-style file extension detected"
            )

        # Rule 2: High entropy
        entropy = features.get("entropy", 0.0)

        if entropy >= self.HIGH_ENTROPY_THRESHOLD:
            rules_triggered.append("HIGH_ENTROPY")

            reasons.append(
                f"High file entropy detected ({entropy:.4f})"
            )

        # Rule 3: Rapid mass modification
        # Require a stronger burst than generic bulk activity to reduce
        # false positives while still catching ransomware-like behavior.
        if files_in_window >= self.MASS_MODIFICATION_THRESHOLD:
            rules_triggered.append("MASS_MODIFICATION")

            reasons.append(
                f"{files_in_window} unique files modified "
                f"within the monitoring window"
            )
        elif (
            files_in_window >= self.MODERATE_MODIFICATION_THRESHOLD
            and features.get("is_suspicious_extension", False)
        ):
            rules_triggered.append("MASS_MODIFICATION")

            reasons.append(
                f"{files_in_window} unique files modified with suspicious "
                "extension patterns in the monitoring window"
            )

        suspicious = len(rules_triggered) > 0

        return {
            "suspicious": suspicious,
            "rules_triggered": rules_triggered,
            "reasons": reasons,
            "entropy": entropy,
            "files_in_window": files_in_window,
        }