"""
Ransomware Detection & Response System
=======================================
Entry point — provides a CLI to start the monitor or run the simulator.

Usage
-----
  # Monitor a directory (default: test_data/)
  python main.py monitor

  # Monitor a custom directory
  python main.py monitor --directory path/to/watch

  # Run the safe ransomware behaviour simulation
  python main.py simulate

  # Retrain the ML model from the dataset
  python main.py train

  # Test the trained ML model with sample data
  python main.py test-model
"""

import argparse
import sys

from src.utils.logger import get_logger

logger = get_logger("ransomware.main")


def cmd_monitor(args):
    """Start real-time filesystem monitoring."""
    from src.monitor.file_monitor import start_monitor

    directory = args.directory
    logger.info("Starting ransomware monitor on: %s", directory)

    try:
        start_monitor(directory)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user.")


def cmd_simulate(_args):
    """Run the safe ransomware behaviour simulation."""
    from src.simulation.ransomware_simulator import main as run_simulation

    logger.info("Starting safe ransomware simulation...")
    run_simulation()


def cmd_train(_args):
    """Retrain the Random Forest ML model."""
    from src.detection.train_model import train

    logger.info("Starting ML model training...")
    train()


def cmd_test_model(_args):
    """Test the trained ML model with sample data."""
    from src.detection.test_model import test_model

    logger.info("Testing ML model...")
    test_model()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Ransomware Detection & Response System",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    # ── monitor ──────────────────────────────────────────────
    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Start real-time filesystem monitoring.",
    )
    monitor_parser.add_argument(
        "--directory",
        default="test_data",
        metavar="DIR",
        help="Directory to monitor (default: test_data).",
    )
    monitor_parser.set_defaults(func=cmd_monitor)

    # ── simulate ─────────────────────────────────────────────
    sim_parser = subparsers.add_parser(
        "simulate",
        help="Run the safe ransomware behaviour simulation.",
    )
    sim_parser.set_defaults(func=cmd_simulate)

    # ── train ────────────────────────────────────────────────
    train_parser = subparsers.add_parser(
        "train",
        help="Retrain the ML model from data/ransomware_dataset.csv.",
    )
    train_parser.set_defaults(func=cmd_train)

    # ── test-model ───────────────────────────────────────────
    test_parser = subparsers.add_parser(
        "test-model",
        help="Test the trained ML model with built-in sample data.",
    )
    test_parser.set_defaults(func=cmd_test_model)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
