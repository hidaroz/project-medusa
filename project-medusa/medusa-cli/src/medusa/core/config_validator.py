"""
Configuration validation
"""
from typing import List, Dict, Any


def validate_config(config: Dict[str, Any]) -> List[str]:
    """
    Validate configuration and return warnings

    Args:
        config: Configuration dictionary

    Returns:
        List of warning messages
    """
    warnings = []

    # Check LLM configuration
    llm_config = config.get("llm", {})

    # Temperature check
    temperature = llm_config.get("temperature", 0.7)
    if temperature > 1.0:
        warnings.append(
            f"⚠️  LLM temperature is {temperature} (> 1.0) - may produce erratic results. "
            "Recommended: 0.7"
        )
    elif temperature < 0.1:
        warnings.append(
            f"⚠️  LLM temperature is {temperature} (< 0.1) - may produce overly deterministic results. "
            "Recommended: 0.7"
        )

    # Max tokens check
    max_tokens = llm_config.get("max_tokens", 2048)
    if max_tokens < 512:
        warnings.append(
            f"⚠️  Max tokens is {max_tokens} - may truncate complex responses. "
            "Recommended: 2048+"
        )
    elif max_tokens > 8192:
        warnings.append(
            f"⚠️  Max tokens is {max_tokens} - may incur higher costs. "
            "Recommended: 2048-4096"
        )

    # Timeout check
    timeout = llm_config.get("timeout", 30)
    if timeout < 10:
        warnings.append(
            f"⚠️  Request timeout is {timeout}s - may timeout on complex queries. "
            "Recommended: 30s"
        )

    # Risk tolerance checks
    risk_tolerance = config.get("risk_tolerance", {})
    auto_approve_low = risk_tolerance.get("auto_approve_low", False)
    auto_approve_medium = risk_tolerance.get("auto_approve_medium", False)
    auto_approve_high = risk_tolerance.get("auto_approve_high", False)

    if auto_approve_high:
        warnings.append(
            "⚠️  Auto-approval for HIGH risk actions is enabled - this is dangerous! "
            "Consider disabling for production use."
        )

    if auto_approve_medium and auto_approve_high:
        warnings.append(
            "⚠️  Auto-approval for both MEDIUM and HIGH risk is enabled - "
            "ensure you have proper authorization for automated testing."
        )

    # API key check
    api_key = config.get("api_key")
    if not api_key or api_key in ["mock", ""]:
        warnings.append(
            "ℹ️  Using mock mode - LLM responses will be simulated. "
            "Configure a real API key for full functionality."
        )

    # Target check
    target_config = config.get("target", {})
    target_url = target_config.get("url")
    if not target_url:
        warnings.append(
            "ℹ️  No default target configured - you'll need to specify --target for each run."
        )
    elif "localhost" not in target_url and "127.0.0.1" not in target_url:
        warnings.append(
            f"⚠️  Default target is '{target_url}' - ensure you have authorization to test this system!"
        )

    # Logging checks
    logging_config = config.get("logging", {})
    if not logging_config.get("save_logs", True):
        warnings.append(
            "ℹ️  Log saving is disabled - you won't have operation history for reports."
        )

    # Reporting checks
    reporting_config = config.get("reporting", {})
    if not reporting_config.get("auto_generate", True):
        warnings.append(
            "ℹ️  Auto report generation is disabled - you'll need to generate reports manually."
        )

    return warnings


def validate_and_display(config: Dict[str, Any]) -> bool:
    """
    Validate configuration and display warnings

    Args:
        config: Configuration dictionary

    Returns:
        True if validation passed (with or without warnings), False if critical errors
    """
    from rich.console import Console
    console = Console()

    warnings = validate_config(config)

    if warnings:
        console.print("\n[bold yellow]Configuration Warnings:[/bold yellow]\n")
        for warning in warnings:
            console.print(f"  {warning}")
        console.print()
        return True
    else:
        console.print("[green]✓[/] Configuration validation passed")
        return True
