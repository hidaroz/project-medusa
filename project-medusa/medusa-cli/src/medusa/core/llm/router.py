"""
Intelligent LLM model routing
Routes tasks to appropriate models based on complexity and cost
"""

from enum import Enum
from typing import Dict, Any, Optional
from .config import LLMConfig


class TaskComplexity(Enum):
    """Task complexity levels for model routing"""
    SIMPLE = "simple"       # Tool parsing, data extraction
    MODERATE = "moderate"   # Analysis, recommendations
    COMPLEX = "complex"     # Strategic planning, multi-step reasoning


class ModelRouter:
    """
    Routes LLM requests to appropriate models based on task complexity

    Strategy:
    - SIMPLE tasks → Haiku (fast, cheap)
    - MODERATE tasks → Haiku (still capable)
    - COMPLEX tasks → Sonnet (deep reasoning)
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.smart_model = config.smart_model
        self.fast_model = config.fast_model

    def select_model(self, task_type: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Select appropriate model for task

        Args:
            task_type: Type of task (e.g., "parse_nmap", "plan_attack")
            context: Additional context for routing decision

        Returns:
            Model identifier string
        """
        complexity = self._assess_complexity(task_type, context)

        if complexity == TaskComplexity.COMPLEX:
            return self.smart_model
        else:
            return self.fast_model

    def _assess_complexity(
        self,
        task_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TaskComplexity:
        """Assess task complexity"""

        # Complex tasks requiring deep reasoning
        complex_tasks = {
            "orchestrate_operation",
            "plan_attack_strategy",
            "assess_risk_holistic",
            "generate_executive_report",
            "analyze_attack_graph",
            "strategic_planning",
            "multi_step_reasoning",
            "complex_decision_making"
        }

        # Simple tasks - tool parsing, extraction
        simple_tasks = {
            "parse_nmap_output",
            "extract_vulnerabilities",
            "format_report",
            "validate_target",
            "check_tool_availability",
            "parse_tool_output",
            "extract_data",
            "simple_classification"
        }

        if task_type in complex_tasks:
            return TaskComplexity.COMPLEX
        elif task_type in simple_tasks:
            return TaskComplexity.SIMPLE
        else:
            # Default to moderate for unknown tasks
            return TaskComplexity.MODERATE

    def get_routing_info(self) -> Dict[str, Any]:
        """Get information about routing configuration"""
        return {
            "smart_model": self.smart_model,
            "fast_model": self.fast_model,
            "routing_strategy": "complexity-based",
            "complexity_levels": {
                "simple": "Fast model (Haiku) - Tool parsing, data extraction",
                "moderate": "Fast model (Haiku) - Analysis, recommendations",
                "complex": "Smart model (Sonnet) - Strategic planning, reasoning"
            }
        }
