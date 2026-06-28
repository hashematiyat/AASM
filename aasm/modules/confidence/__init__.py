"""
Feature 7 — Confidence Engine
Aggregates signals from all detection engines into a unified confidence score.
"""

from .engine import ConfidenceEngine, ConfidenceResult, SignalWeight

__all__ = [
    "ConfidenceEngine",
    "ConfidenceResult",
    "SignalWeight",
]
