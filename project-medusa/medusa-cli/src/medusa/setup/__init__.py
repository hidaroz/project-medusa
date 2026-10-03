"""
MEDUSA Setup Module
Provides interactive setup, configuration validation, and profile management.
"""

from .wizard import SetupWizard
from .validator import ConfigValidator
from .profiles import ProfileManager
from .auto_detect import ToolDetector

__all__ = [
    "SetupWizard",
    "ConfigValidator",
    "ProfileManager",
    "ToolDetector",
]
