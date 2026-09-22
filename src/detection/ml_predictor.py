from pathlib import Path

import joblib
import pandas as pd


class MLPredictor:
    """
    Load the trained ransomware ML model
    and predict ransomware-like activity.
    """

    MODEL_PATH = Path("models/ransomware_detector.joblib")

    FEATURES = [
        "file_size",
        "entropy",
        "files_in_window",
        "extension_risk",
        "modification_rate",
    ]

    def __init__(self):
        self.model_path = Path(self.MODEL_PATH)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.model_path.exists():
            from src.detection.train_model import train

            train()

        self.model = joblib.load(self.model_path)

    def predict(self, features):
        """
        Predict whether the observed behavior
        is ransomware-like.

        Returns:
            prediction: 0 or 1
            probability: ransomware probability
        """

        data = pd.DataFrame([{
            feature: features.get(feature, 0)
            for feature in self.FEATURES
        }])

        prediction = int(
            self.model.predict(data)[0]
        )

        probabilities = self.model.predict_proba(data)[0]

        ransomware_probability = float(
            probabilities[1]
        )

        return {
            "prediction": prediction,
            "ransomware_probability": ransomware_probability,
            "is_ransomware": prediction == 1,
        }