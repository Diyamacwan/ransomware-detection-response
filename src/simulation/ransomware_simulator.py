"""
Safe ransomware behaviour simulator.

Stages
------
1. Create 25 harmless text files.
2. Rapidly modify all 25 (triggers MASS_MODIFICATION → HIGH/CRITICAL alert).
3. Create files with ransomware-style extensions (triggers SUSPICIOUS_EXTENSION).
4. Write high-entropy binary data to files (triggers HIGH_ENTROPY rule).
5. Drop a fake ransom note (triggers keyword detection if enabled).

No real encryption or deletion ever happens.
"""

import os
import random
import time
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger("ransomware.simulator")

TEST_DIRECTORY       = Path("test_data")
SIMULATION_DIRECTORY = TEST_DIRECTORY / "simulation_test"

NORMAL_FILE_COUNT   = 25
ENCRYPTED_EXT_COUNT = 8


# ── helpers ──────────────────────────────────────────────────────────────

def _write(path: Path, content: bytes | str, mode: str = "w", encoding="utf-8"):
    if mode == "wb":
        path.write_bytes(content)
    else:
        path.write_text(content, encoding=encoding)


# ── Stage 1: create normal files ─────────────────────────────────────────

def create_test_files():
    SIMULATION_DIRECTORY.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("STAGE 1 — Creating %s harmless test files", NORMAL_FILE_COUNT)
    logger.info("=" * 60)

    for i in range(1, NORMAL_FILE_COUNT + 1):
        path = SIMULATION_DIRECTORY / f"document_{i}.txt"
        _write(path, f"Harmless test file #{i}.\nContent: normal document data.\n")

    logger.info("[+] Stage 1 complete — %s files created.", NORMAL_FILE_COUNT)


# ── Stage 2: rapid mass modification ─────────────────────────────────────

def simulate_rapid_modification():
    logger.info("=" * 60)
    logger.info("STAGE 2 — Simulating rapid mass modification (triggers MASS_MODIFICATION rule)")
    logger.info("=" * 60)

    for i in range(1, NORMAL_FILE_COUNT + 1):
        path = SIMULATION_DIRECTORY / f"document_{i}.txt"
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[MODIFIED round 1] Suspicious activity simulation #{i}.\n")
        logger.info("[MODIFIED] %s", path.name)
        time.sleep(0.12)

    # Second wave — keeps files_in_window high to push risk to CRITICAL
    logger.info("  > Second modification wave...")
    for i in range(1, NORMAL_FILE_COUNT + 1):
        path = SIMULATION_DIRECTORY / f"document_{i}.txt"
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[MODIFIED round 2] Escalation wave #{i}.\n")
        time.sleep(0.08)

    logger.info("[+] Stage 2 complete.")


# ── Stage 3: suspicious extensions ───────────────────────────────────────

def simulate_suspicious_extensions():
    logger.info("=" * 60)
    logger.info("STAGE 3 — Creating ransomware-extension files (triggers SUSPICIOUS_EXTENSION rule)")
    logger.info("=" * 60)

    extensions = [".locked", ".encrypted", ".enc", ".crypt", ".wncry", ".zepto", ".locky", ".crypto"]

    for i in range(1, ENCRYPTED_EXT_COUNT + 1):
        ext  = extensions[(i - 1) % len(extensions)]
        path = SIMULATION_DIRECTORY / f"document_{i}{ext}"
        _write(path, f"Harmless suspicious-extension test #{i}.\n")
        logger.info("[CREATED] %s", path.name)
        time.sleep(0.15)

    logger.info("[+] Stage 3 complete.")


# ── Stage 4: high-entropy binary files ───────────────────────────────────

def simulate_high_entropy():
    logger.info("=" * 60)
    logger.info("STAGE 4 — Writing high-entropy binary data (triggers HIGH_ENTROPY rule)")
    logger.info("=" * 60)

    for i in range(1, 6):
        path = SIMULATION_DIRECTORY / f"encrypted_payload_{i}.enc"
        # Pure random bytes → Shannon entropy ≈ 7.9–8.0
        _write(path, os.urandom(64 * 1024), mode="wb")
        logger.info("[CREATED] %s (high-entropy binary, %s KB)", path.name, 64)
        time.sleep(0.2)

    logger.info("[+] Stage 4 complete.")


# ── Stage 5: ransom note ──────────────────────────────────────────────────

def drop_ransom_note():
    logger.info("=" * 60)
    logger.info("STAGE 5 — Dropping ransom note (maximum threat signal)")
    logger.info("=" * 60)

    note_content = (
        "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\n\n"
        "All your important documents, photos and databases have been encrypted.\n\n"
        "To decrypt your files you need to pay 0.05 bitcoin to the following address:\n"
        "  1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWx\n\n"
        "After payment, send your transaction ID to: decrypt@example.onion\n\n"
        "You have 72 hours to comply. After that your files will be permanently deleted.\n\n"
        "--- DO NOT attempt to restore files yourself ---\n"
        "--- DO NOT contact law enforcement           ---\n"
        "--- YOUR UNIQUE ID: RNS-$(random)-2024      ---\n"
    )

    for name in ["README_DECRYPT.txt", "HOW_TO_DECRYPT.html", "YOUR_FILES_ARE_LOCKED.txt"]:
        path = SIMULATION_DIRECTORY / name
        _write(path, note_content)
        logger.info("[CREATED] %s  ← ransom note dropped!", path.name)
        time.sleep(0.3)

    logger.info("[+] Stage 5 complete.")


# ── main ──────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("SAFE RANSOMWARE BEHAVIOUR SIMULATION")
    logger.info("No real encryption, deletion or malware execution occurs.")
    logger.info("=" * 60)

    # Stage 1
    create_test_files()
    time.sleep(1)

    # Stage 2
    simulate_rapid_modification()
    time.sleep(1.5)

    # Stage 3
    simulate_suspicious_extensions()
    time.sleep(1)

    # Stage 4
    simulate_high_entropy()
    time.sleep(1)

    # Stage 5
    drop_ransom_note()

    logger.info("=" * 60)
    logger.info("SIMULATION COMPLETED — Check dashboard at http://127.0.0.1:5000")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
