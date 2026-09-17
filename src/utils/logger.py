import logging
import sys
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "ransomware_detection.log"

# Log format: timestamp | level | message
_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger that writes to both the console
    and a persistent log file (logs/ransomware_detection.log).

    All loggers share the same handlers — the file and console
    are only attached once to the root 'ransomware' logger.
    """

    logger = logging.getLogger(name)

    # Only configure handlers on the root application logger
    # the first time this is called.
    root = logging.getLogger("ransomware")

    if not root.handlers:
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        formatter = logging.Formatter(
            fmt=_FORMAT,
            datefmt=_DATE_FORMAT,
        )

        # Console handler — INFO and above
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        # File handler — DEBUG and above (full detail)
        file_handler = logging.FileHandler(
            LOG_FILE,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        root.setLevel(logging.DEBUG)
        root.addHandler(console_handler)
        root.addHandler(file_handler)

    return logger
