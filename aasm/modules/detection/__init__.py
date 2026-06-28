"""
Smart Detection Engine — confidence-based multi-signal platform detection.
"""

from .engine import SmartDetectionEngine, PlatformDetectionResult
from .signatures import PLATFORM_SIGNATURES

__all__ = [
    "SmartDetectionEngine",
    "PlatformDetectionResult",
    "PLATFORM_SIGNATURES",
]
