from pathlib import Path
import time

from src.utils.logger import get_logger

logger = get_logger("ransomware.simulator")

TEST_DIRECTORY = Path("test_data")
SIMULATION_DIRECTORY = TEST_DIRECTORY / "simulation_test"

FILE_COUNT = 15


def create_test_files():
    """Create harmless files for the simulation."""

    SIMULATION_DIRECTORY.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("SAFE RANSOMWARE BEHAVIOR SIMULATION")
    logger.info("=" * 60)
    logger.info("Creating %s harmless test files...", FILE_COUNT)

    for i in range(1, FILE_COUNT + 1):
        file_path = SIMULATION_DIRECTORY / f"document_{i}.txt"

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(
                "This is a harmless ransomware "
                "detection test file.\n"
            )

    logger.info("[+] Test files created.")


def simulate_rapid_modification():
    """
    Rapidly modify the harmless files.

    This simulates the filesystem behavior that
    ransomware detectors monitor.
    """

    logger.info("Simulating rapid file modifications...")

    for i in range(1, FILE_COUNT + 1):
        file_path = SIMULATION_DIRECTORY / f"document_{i}.txt"

        with open(file_path, "a", encoding="utf-8") as file:
            file.write("Suspicious activity simulation.\n")

        logger.info("[MODIFIED] %s", file_path)

        # Small delay to keep modifications inside
        # the monitor's behavior window.
        time.sleep(0.15)

    logger.info("[+] Rapid modification simulation completed.")


def simulate_suspicious_extensions():
    """
    Create harmless files using ransomware-style extensions.

    No encryption is performed.
    """

    logger.info("Creating suspicious-extension test files...")

    for i in range(1, 6):
        file_path = SIMULATION_DIRECTORY / f"document_{i}.locked"

        with open(file_path, "w", encoding="utf-8") as file:
            file.write("Harmless suspicious-extension test.\n")

        logger.info("[CREATED] %s", file_path)

        time.sleep(0.15)

    logger.info("[+] Suspicious-extension simulation completed.")


def main():
    """Run the complete safe simulation."""

    logger.info("[!] SAFE SIMULATION ONLY")
    logger.info(
        "[!] No encryption, deletion, or malware execution will occur."
    )

    create_test_files()
    time.sleep(1)

    simulate_rapid_modification()
    time.sleep(1)

    simulate_suspicious_extensions()

    logger.info("=" * 60)
    logger.info("SIMULATION COMPLETED")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
