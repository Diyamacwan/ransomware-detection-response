import joblib
import pandas as pd

from src.utils.logger import get_logger

logger = get_logger("ransomware.test_model")

MODEL_PATH = "models/ransomware_detector.joblib"

FEATURES = [
    "file_size",
    "entropy",
    "files_in_window",
    "extension_risk",
    "modification_rate",
]


def test_model():
    logger.info("=" * 60)
    logger.info("RANSOMWARE ML MODEL PREDICTION TEST")
    logger.info("=" * 60)

    model = joblib.load(MODEL_PATH)
    logger.info("[+] Model loaded successfully.")

    # Normal activity example
    normal_sample = pd.DataFrame([{
        "file_size": 150000,
        "entropy": 3.5,
        "files_in_window": 2,
        "extension_risk": 0,
        "modification_rate": 0.8,
    }])

    # Ransomware-like activity example
    ransomware_sample = pd.DataFrame([{
        "file_size": 2500000,
        "entropy": 7.2,
        "files_in_window": 25,
        "extension_risk": 1,
        "modification_rate": 20.0,
    }])

    samples = {
        "NORMAL": normal_sample,
        "RANSOMWARE-LIKE": ransomware_sample,
    }

    for name, sample in samples.items():
        prediction = model.predict(sample[FEATURES])[0]
        probability = model.predict_proba(sample[FEATURES])[0]

        logger.info("-" * 60)
        logger.info("Test case  : %s", name)
        logger.info("Prediction : %s", prediction)
        logger.info(
            "Normal probability     : %.2f%%", probability[0] * 100
        )
        logger.info(
            "Ransomware probability : %.2f%%", probability[1] * 100
        )

        if prediction == 1:
            logger.warning("Result: RANSOMWARE-LIKE ACTIVITY")
        else:
            logger.info("Result: NORMAL ACTIVITY")

    logger.info("=" * 60)
    logger.info("MODEL PREDICTION TEST COMPLETED")
    logger.info("=" * 60)


if __name__ == "__main__":
    test_model()
