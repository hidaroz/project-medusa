"""
Configuration Validator
Validates MEDUSA configuration files
"""

from typing import Dict, Any, Tuple, List
import ipaddress
from pathlib import Path


class ConfigValidator:
    """Validates MEDUSA configuration"""

    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate configuration

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Validate LLM configuration
        llm_errors = self._validate_llm(config.get("llm", {}))
        errors.extend(llm_errors)

        # Validate database configuration
        db_errors = self._validate_databases(config.get("databases", {}))
        errors.extend(db_errors)

        # Validate safety configuration
        safety_errors = self._validate_safety(config.get("safety", {}))
        errors.extend(safety_errors)

        # Validate output configuration
        output_errors = self._validate_output(config.get("output", {}))
        errors.extend(output_errors)

        # Validate performance configuration
        perf_errors = self._validate_performance(config.get("performance", {}))
        errors.extend(perf_errors)

        return (len(errors) == 0, errors)

    def _validate_llm(self, llm_config: Dict[str, Any]) -> List[str]:
        """Validate LLM configuration"""
        errors = []

        if not llm_config:
            errors.append("LLM configuration is required")
            return errors

        # Provider is required
        provider = llm_config.get("provider")
        if not provider:
            errors.append("LLM provider is required")
        elif provider not in ["bedrock", "anthropic", "openai", "ollama", "mistral"]:
            errors.append(f"Invalid LLM provider: {provider}")

        # Model is required
        if not llm_config.get("model"):
            errors.append("LLM model is required")

        # Validate provider-specific settings
        if provider == "bedrock":
            if not llm_config.get("region"):
                errors.append("AWS region is required for Bedrock")

        elif provider in ["anthropic", "openai", "mistral"]:
            if not llm_config.get("api_key"):
                errors.append(f"API key is required for {provider}")

        elif provider == "ollama":
            if not llm_config.get("base_url"):
                errors.append("Base URL is required for Ollama")

        # Validate temperature
        temperature = llm_config.get("temperature", 0.3)
        if not isinstance(temperature, (int, float)) or temperature < 0 or temperature > 1:
            errors.append("Temperature must be between 0.0 and 1.0")

        # Validate max_tokens
        max_tokens = llm_config.get("max_tokens", 4096)
        if not isinstance(max_tokens, int) or max_tokens < 1:
            errors.append("max_tokens must be a positive integer")

        return errors

    def _validate_databases(self, db_config: Dict[str, Any]) -> List[str]:
        """Validate database configuration"""
        errors = []

        # Neo4j validation
        if "neo4j" in db_config:
            neo4j = db_config["neo4j"]

            if not neo4j.get("uri"):
                errors.append("Neo4j URI is required")
            elif not neo4j["uri"].startswith(("bolt://", "neo4j://", "bolt+s://", "neo4j+s://")):
                errors.append("Invalid Neo4j URI scheme")

            if not neo4j.get("user"):
                errors.append("Neo4j user is required")

            if not neo4j.get("password"):
                errors.append("Neo4j password is required")

        # ChromaDB validation
        if "chromadb" in db_config:
            chroma = db_config["chromadb"]

            if not chroma.get("path"):
                errors.append("ChromaDB path is required")

            if not chroma.get("collection"):
                errors.append("ChromaDB collection name is required")

        return errors

    def _validate_safety(self, safety_config: Dict[str, Any]) -> List[str]:
        """Validate safety configuration"""
        errors = []

        # Validate authorized scope
        if "authorized_scope" in safety_config:
            scope = safety_config["authorized_scope"]
            if not isinstance(scope, list):
                errors.append("authorized_scope must be a list")
            else:
                for cidr in scope:
                    try:
                        ipaddress.ip_network(cidr)
                    except ValueError:
                        errors.append(f"Invalid CIDR notation: {cidr}")

        # Validate audit log path
        if "audit_log" in safety_config:
            log_path = Path(safety_config["audit_log"])
            if not log_path.parent.exists():
                errors.append(f"Audit log directory does not exist: {log_path.parent}")

        # Validate emergency_stop_key if present
        if "emergency_stop_key" in safety_config:
            key = safety_config["emergency_stop_key"]
            valid_keys = ["ctrl+c", "ctrl+alt+e", "escape"]
            if key not in valid_keys:
                errors.append(f"Invalid emergency_stop_key: {key}")

        return errors

    def _validate_output(self, output_config: Dict[str, Any]) -> List[str]:
        """Validate output configuration"""
        errors = []

        # Validate format
        if "format" in output_config:
            format_type = output_config["format"]
            valid_formats = ["rich", "json", "plain", "markdown"]
            if format_type not in valid_formats:
                errors.append(f"Invalid output format: {format_type}")

        # Validate verbosity
        if "verbosity" in output_config:
            verbosity = output_config["verbosity"]
            valid_levels = ["debug", "info", "warning", "error"]
            if verbosity not in valid_levels:
                errors.append(f"Invalid verbosity level: {verbosity}")

        return errors

    def _validate_performance(self, perf_config: Dict[str, Any]) -> List[str]:
        """Validate performance configuration"""
        errors = []

        # Validate max_threads
        if "max_threads" in perf_config:
            max_threads = perf_config["max_threads"]
            if not isinstance(max_threads, int) or max_threads < 1:
                errors.append("max_threads must be a positive integer")
            elif max_threads > 100:
                errors.append("max_threads should not exceed 100")

        # Validate timeout
        if "timeout" in perf_config:
            timeout = perf_config["timeout"]
            if not isinstance(timeout, int) or timeout < 1:
                errors.append("timeout must be a positive integer")

        # Validate rate_limit
        if "rate_limit" in perf_config:
            rate_limit = perf_config["rate_limit"]
            if not isinstance(rate_limit, int) or rate_limit < 1:
                errors.append("rate_limit must be a positive integer")

        return errors

    def validate_file(self, config_path: Path) -> Tuple[bool, List[str]]:
        """
        Validate a configuration file

        Args:
            config_path: Path to configuration file

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        import yaml

        errors = []

        if not config_path.exists():
            return False, [f"Configuration file not found: {config_path}"]

        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                return False, ["Configuration must be a YAML dictionary"]

            return self.validate(config)

        except yaml.YAMLError as e:
            return False, [f"Invalid YAML: {e}"]
        except Exception as e:
            return False, [f"Error reading configuration: {e}"]

    def get_recommendations(self, config: Dict[str, Any]) -> List[str]:
        """
        Get configuration recommendations (not errors, just suggestions)

        Args:
            config: Configuration dictionary

        Returns:
            List of recommendations
        """
        recommendations = []

        # LLM recommendations
        llm_config = config.get("llm", {})
        if llm_config.get("temperature", 0.3) > 0.7:
            recommendations.append(
                "High temperature (>0.7) may produce less deterministic results. "
                "Consider lowering for more consistent behavior."
            )

        # Safety recommendations
        safety_config = config.get("safety", {})
        if not safety_config.get("require_authorization"):
            recommendations.append(
                "Authorization is disabled. Consider enabling for additional safety."
            )

        if not safety_config.get("auto_rollback"):
            recommendations.append(
                "Auto-rollback is disabled. Failed exploits may leave artifacts."
            )

        if not safety_config.get("audit_log"):
            recommendations.append(
                "Audit logging is not configured. Consider enabling for compliance."
            )

        # Performance recommendations
        perf_config = config.get("performance", {})
        max_threads = perf_config.get("max_threads", 10)
        if max_threads > 50:
            recommendations.append(
                f"High thread count ({max_threads}) may cause resource issues. "
                "Consider reducing if you experience problems."
            )

        # Database recommendations
        db_config = config.get("databases", {})
        if not db_config.get("neo4j"):
            recommendations.append(
                "Neo4j is not configured. Graph database provides better context "
                "for attack path analysis."
            )

        if not db_config.get("chromadb"):
            recommendations.append(
                "ChromaDB is not configured. Vector database enhances RAG capabilities."
            )

        return recommendations
