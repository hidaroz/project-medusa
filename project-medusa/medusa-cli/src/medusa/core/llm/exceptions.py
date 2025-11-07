"""
Custom exceptions for LLM operations.
"""


class LLMError(Exception):
    """Base exception for all LLM-related errors"""
    pass


class LLMConnectionError(LLMError):
    """Raised when cannot connect to LLM provider"""
    pass


class LLMTimeoutError(LLMError):
    """Raised when LLM request times out"""
    pass


class LLMConfigurationError(LLMError):
    """Raised when LLM configuration is invalid"""
    pass


class LLMModelNotFoundError(LLMError):
    """Raised when specified model is not available"""
    pass
