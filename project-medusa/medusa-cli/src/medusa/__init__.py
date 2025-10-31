"""
MEDUSA - AI-Powered Penetration Testing CLI

An autonomous penetration testing framework that uses Large Language Models
to intelligently test system security.

For authorized security testing purposes only.
"""

__version__ = "1.0.0"
__author__ = "Project Medusa Team"
__license__ = "MIT"

from medusa.config import Config, get_config

__all__ = ["Config", "get_config", "__version__"]

