"""Compatibility wrapper for behavior detection utilities.

This module exposes a small, package-friendly facade over the active
behavior analysis implementation used by the project.
"""

from src.detection.behavior_analyzer import BehaviorAnalyzer


class BehaviorDetector(BehaviorAnalyzer):
    """Backward-compatible alias for the project’s behavior analyzer."""

    pass
