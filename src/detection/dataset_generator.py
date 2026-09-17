import csv
import random
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger("ransomware.dataset_generator")

DATASET_PATH = Path("data/ransomware_dataset.csv")

NORMAL_EXTENSIONS = [".txt", ".docx", ".jpg", ".png", ".pdf", ".xlsx"]
SUSPICIOUS_EXTENSIONS = [".locked", ".encrypted", ".enc", ".crypt"]


def generate_normal_sample():
    file_size = random.randint(100, 500000)
    entropy = round(random.uniform(2.5, 5.5), 4)
    files_in_window = random.randint(1, 4)
    modification_rate = round(random.uniform(0.1, 2.0), 2)
    extension_risk = 0
    return [file_size, entropy, files_in_window, extension_risk, modification_rate, 0]


def generate_ransomware_sample():
    file_size = random.randint(1000, 5000000)
    entropy = round(random.uniform(6.0, 8.0), 4)
    files_in_window = random.randint(8, 50)
    modification_rate = round(random.uniform(5.0, 30.0), 2)
    extension_risk = 1
    return [file_size, entropy, files_in_window, extension_risk, modification_rate, 1]


def create_dataset(normal_samples=100, ransomware_samples=100):
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for _ in range(normal_samples):
        rows.append(generate_normal_sample())

    for _ in range(ransomware_samples):
        rows.append(generate_ransomware_sample())

    random.shuffle(rows)

    headers = [
        "file_size",
        "entropy",
        "files_in_window",
        "extension_risk",
        "modification_rate",
        "label",
    ]

    with open(DATASET_PATH, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)

    logger.info("=" * 60)
    logger.info("DATASET CREATED")
    logger.info("=" * 60)
    logger.info("Location            : %s", DATASET_PATH)
    logger.info("Normal samples      : %s", normal_samples)
    logger.info("Ransomware samples  : %s", ransomware_samples)
    logger.info("Total samples       : %s", normal_samples + ransomware_samples)
    logger.info("=" * 60)


if __name__ == "__main__":
    create_dataset()
