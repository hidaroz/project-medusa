"""
Strategy Selector for MEDUSA
Uses feedback from past operations to select optimal techniques and strategies
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging
from medusa.core.feedback import get_feedback_tracker
from medusa.core.objective_parser import ObjectiveStrategy

logger = logging.getLogger(__name__)


@dataclass
class TechniqueRecommendation:
    """Recommendation for a technique based on feedback"""
    technique_id: str
    technique_name: str
    success_rate: float
    usage_count: int
    confidence: float  # How confident we are in this recommendation
    reason: str  # Why this technique is recommended


class StrategySelector:
    """
    Selects optimal techniques and strategies based on feedback from past operations

    This class analyzes feedback data to:
    - Identify techniques that work well for specific objectives
    - Avoid techniques that have failed in the past
    - Prioritize techniques with high success rates
    """

    def __init__(self):
        self.feedback_tracker = get_feedback_tracker()

    def select_techniques(
        self,
        objective_strategy: Optional[ObjectiveStrategy],
        limit: int = 5
    ) -> List[TechniqueRecommendation]:
        """
        Select best techniques for the given objective strategy

        Args:
            objective_strategy: The objective strategy (contains focus areas, relevant techniques)
            limit: Maximum number of techniques to return

        Returns:
            List of recommended techniques, sorted by confidence
        """
        if not objective_strategy:
            # No objective, return general best techniques
            return self._get_general_best_techniques(limit)

        # Get objective-specific recommendations
        recommendations = []

        # Get all technique feedback
        all_techniques = self.feedback_tracker.get_all_technique_feedback()

        # If no techniques in feedback yet, return empty list
        if not all_techniques:
            logger.info("No technique feedback available yet, using default strategy")
            return []

        # Filter by objective if possible
        focus_areas = objective_strategy.focus_areas

        for technique_id, feedback in all_techniques.items():
            # Check if technique is relevant to objective
            if objective_strategy.relevant_techniques:
                if technique_id not in objective_strategy.relevant_techniques:
                    continue  # Skip techniques not relevant to objective

            # Calculate success rate
            total_attempts = feedback.get('success_count', 0) + feedback.get('failure_count', 0)
            if total_attempts == 0:
                # No feedback yet, use default confidence
                success_rate = 0.5
                confidence = 0.3  # Low confidence for untested techniques
            else:
                success_rate = feedback.get('success_count', 0) / total_attempts
                # Higher confidence with more data
                confidence = min(0.9, 0.5 + (total_attempts / 10) * 0.1)

            # Check objective-specific performance if available
            objective_performance = feedback.get('objective_performance', {})
            if focus_areas and objective_performance:
                # Check if this technique has been used for similar objectives
                for focus_area in focus_areas:
                    if focus_area in objective_performance:
                        area_perf = objective_performance[focus_area]
                        area_attempts = area_perf.get('success_count', 0) + area_perf.get('failure_count', 0)
                        if area_attempts > 0:
                            # Use objective-specific success rate
                            success_rate = area_perf.get('success_count', 0) / area_attempts
                            confidence = min(0.95, 0.6 + (area_attempts / 5) * 0.1)
                            break

            # Generate reason
            if total_attempts == 0:
                reason = "Not yet tested, but relevant to objective"
            elif success_rate > 0.7:
                reason = f"High success rate ({success_rate:.0%}) for this objective"
            elif success_rate > 0.5:
                reason = f"Moderate success rate ({success_rate:.0%})"
            else:
                reason = f"Low success rate ({success_rate:.0%}), but may be worth retrying"

            recommendations.append(TechniqueRecommendation(
                technique_id=technique_id,
                technique_name=feedback.get('technique_name', technique_id),
                success_rate=success_rate,
                usage_count=total_attempts,
                confidence=confidence,
                reason=reason
            ))

        # Sort by confidence and success rate
        recommendations.sort(key=lambda x: (x.confidence, x.success_rate), reverse=True)

        # Filter out very low confidence recommendations
        recommendations = [r for r in recommendations if r.confidence > 0.2]

        return recommendations[:limit]

    def _get_general_best_techniques(self, limit: int) -> List[TechniqueRecommendation]:
        """Get best techniques overall (no objective filter)"""
        all_techniques = self.feedback_tracker.get_all_technique_feedback()
        recommendations = []

        for technique_id, feedback in all_techniques.items():
            total_attempts = feedback.get('success_count', 0) + feedback.get('failure_count', 0)
            if total_attempts == 0:
                continue  # Skip untested techniques for general recommendations

            success_rate = feedback.get('success_count', 0) / total_attempts
            confidence = min(0.9, 0.5 + (total_attempts / 10) * 0.1)

            recommendations.append(TechniqueRecommendation(
                technique_id=technique_id,
                technique_name=feedback.get('technique_name', technique_id),
                success_rate=success_rate,
                usage_count=total_attempts,
                confidence=confidence,
                reason=f"Overall success rate: {success_rate:.0%}"
            ))

        recommendations.sort(key=lambda x: (x.confidence, x.success_rate), reverse=True)
        return recommendations[:limit]

    def get_extraction_method_recommendation(
        self,
        data_type: str,
        objective: Optional[str] = None
    ) -> Tuple[str, float]:
        """
        Recommend best extraction method for a data type

        Args:
            data_type: Type of data to extract (e.g., 'medical_record', 'credential')
            objective: Optional objective for context

        Returns:
            Tuple of (recommended_method, confidence)
            Methods: 'regex', 'llm_gemini', 'llm_ollama', 'api_query'
        """
        # Get extraction feedback from tracker
        extraction_feedback = self.feedback_tracker.get_extraction_feedback()

        # Filter by data type if available
        type_feedback = extraction_feedback.get(data_type, {})

        if not type_feedback:
            # No feedback for this data type, use default
            return ('llm_gemini', 0.5)

        # Calculate success rates for each method
        method_scores: Dict[str, float] = {}

        for method, stats in type_feedback.items():
            total = stats.get('success_count', 0) + stats.get('failure_count', 0)
            if total > 0:
                success_rate = stats.get('success_count', 0) / total
                # Weight by number of attempts
                confidence = min(0.95, 0.5 + (total / 5) * 0.1)
                method_scores[method] = success_rate * confidence

        if not method_scores:
            return ('llm_gemini', 0.5)

        # Return method with highest score
        best_method = max(method_scores.items(), key=lambda x: x[1])
        return (best_method[0], best_method[1])

    def should_avoid_technique(
        self,
        technique_id: str,
        objective_strategy: Optional[ObjectiveStrategy]
    ) -> Tuple[bool, str]:
        """
        Check if a technique should be avoided based on past failures

        Args:
            technique_id: MITRE technique ID
            objective_strategy: Current objective strategy

        Returns:
            Tuple of (should_avoid, reason)
        """
        all_techniques = self.feedback_tracker.get_all_technique_feedback()
        feedback = all_techniques.get(technique_id)

        if not feedback:
            return (False, "No feedback available")

        total_attempts = feedback.get('success_count', 0) + feedback.get('failure_count', 0)
        if total_attempts < 3:
            return (False, "Insufficient data")

        failure_rate = feedback.get('failure_count', 0) / total_attempts

        # Avoid if failure rate > 80% and we have enough data
        if failure_rate > 0.8 and total_attempts >= 5:
            return (True, f"High failure rate ({failure_rate:.0%}) based on {total_attempts} attempts")

        # Check objective-specific failures
        if objective_strategy and objective_strategy.focus_areas:
            objective_performance = feedback.get('objective_performance', {})
            for focus_area in objective_strategy.focus_areas:
                if focus_area in objective_performance:
                    area_perf = objective_performance[focus_area]
                    area_attempts = area_perf.get('success_count', 0) + area_perf.get('failure_count', 0)
                    if area_attempts >= 3:
                        area_failure_rate = area_perf.get('failure_count', 0) / area_attempts
                        if area_failure_rate > 0.8:
                            return (True, f"High failure rate ({area_failure_rate:.0%}) for {focus_area} objective")

        return (False, "Acceptable performance")

