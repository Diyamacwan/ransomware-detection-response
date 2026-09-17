class RiskScorer:
    """
    Calculate a 0-100 ransomware risk score.

    This is a defensive scoring system based on observed
    filesystem behavior.
    """

    MASS_MODIFICATION_SCORE = 40
    HIGH_ENTROPY_SCORE = 30
    SUSPICIOUS_EXTENSION_SCORE = 30

    def calculate_score(self, detection):
        """
        Calculate the risk score from triggered detection rules.
        """

        score = 0

        rules = detection.get("rules_triggered", [])

        if "MASS_MODIFICATION" in rules:
            score += self.MASS_MODIFICATION_SCORE

        if "HIGH_ENTROPY" in rules:
            score += self.HIGH_ENTROPY_SCORE

        if "SUSPICIOUS_EXTENSION" in rules:
            score += self.SUSPICIOUS_EXTENSION_SCORE

        return min(score, 100)

    def get_severity(self, score):
        """
        Convert the numerical score into a severity level.
        """

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"

    def score(self, detection):
        """
        Return complete risk assessment.
        """

        risk_score = self.calculate_score(detection)

        severity = self.get_severity(risk_score)

        return {
            "risk_score": risk_score,
            "severity": severity,
        }