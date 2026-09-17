import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import joblib


DATASET_PATH = Path("data/ransomware_dataset.csv")
MODEL_PATH = Path("models/ransomware_model.pkl")


def train_model():
    print("=" * 60)
    print("RANSOMWARE ML MODEL TRAINING")
    print("=" * 60)

    # Load dataset
    df = pd.read_csv(DATASET_PATH)

    print(f"[+] Dataset loaded: {len(df)} samples")

    # Features used by the model
    features = [
        "file_size",
        "entropy",
        "files_in_window",
        "extension_risk",
        "modification_rate"
    ]

    X = df[features]
    y = df["label"]

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"[+] Training samples: {len(X_train)}")
    print(f"[+] Testing samples : {len(X_test)}")

    # Create Random Forest model
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    # Train
    print("\n[+] Training Random Forest model...")
    model.fit(X_train, y_train)

    # Predict
    y_pred = model.predict(X_test)

    # Accuracy
    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 60)
    print("MODEL RESULTS")
    print("=" * 60)

    print(f"Accuracy: {accuracy * 100:.2f}%")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=["Normal", "Ransomware-like"]
    ))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Feature importance
    print("\nFeature Importance:")
    for feature, importance in zip(features, model.feature_importances_):
        print(f"{feature:20s}: {importance:.4f}")

    # Save model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print("\n[+] Model saved to:", MODEL_PATH)
    print("=" * 60)


if __name__ == "__main__":
    train_model()