from pathlib import Path

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from src.utils.logger import get_logger

logger = get_logger("ransomware.train_model")

DATASET_PATH = "data/ransomware_dataset.csv"
MODEL_PATH = "models/ransomware_detector.joblib"

FEATURES = [
    "file_size",
    "entropy",
    "files_in_window",
    "extension_risk",
    "modification_rate",
]


def train():
    """Train the Random Forest model and save it to disk."""

    logger.info("=" * 60)
    logger.info("RANSOMWARE DETECTION MODEL TRAINING")
    logger.info("=" * 60)

    df = pd.read_csv(DATASET_PATH)

    logger.info("Dataset : %s", DATASET_PATH)
    logger.info("Samples : %s", len(df))

    X = df[FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    logger.info("Training samples : %s", len(X_train))
    logger.info("Testing samples  : %s", len(X_test))

    model = RandomForestClassifier(n_estimators=100, random_state=42)

    logger.info("Training model...")
    model.fit(X_train, y_train)
    logger.info("Training completed.")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    logger.info("=" * 60)
    logger.info("MODEL PERFORMANCE")
    logger.info("=" * 60)
    logger.info("Accuracy : %.4f", accuracy)
    logger.info("Classification Report:\n%s", classification_report(y_test, y_pred))
    logger.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))

    model_dir = Path(MODEL_PATH).parent
    model_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    logger.info("=" * 60)
    logger.info("MODEL SAVED")
    logger.info("=" * 60)
    logger.info("Location : %s", MODEL_PATH)


if __name__ == "__main__":
    train()
