"""
Context Re-ranking
Re-ranks retrieved contexts based on relevance and other factors
"""

from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
import re


class ContextReranker:
    """
    Re-ranks retrieved context results based on multiple factors:
    - Semantic relevance
    - Recency
    - CVE severity
    - MITRE ATT&CK technique phase alignment
    - Historical success rate
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Weights for different ranking factors
        self.weights = {
            "relevance": 0.4,
            "severity": 0.2,
            "recency": 0.15,
            "success_rate": 0.15,
            "phase_alignment": 0.1,
        }

    def rerank(
        self,
        results: List[Dict[str, Any]],
        query: str,
        operation_state: Optional[Dict[str, Any]] = None,
        top_k: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Re-rank results based on multiple factors

        Args:
            results: List of result dictionaries
            query: Original query
            operation_state: Current operation state
            top_k: Return only top K results

        Returns:
            Re-ranked list of results
        """
        if not results:
            return []

        # Calculate composite scores
        scored_results = []
        for result in results:
            score = self._calculate_composite_score(result, query, operation_state)
            scored_results.append({
                **result,
                "_rerank_score": score
            })

        # Sort by score
        ranked_results = sorted(
            scored_results,
            key=lambda x: x["_rerank_score"],
            reverse=True
        )

        # Return top K if specified
        if top_k:
            ranked_results = ranked_results[:top_k]

        return ranked_results

    def _calculate_composite_score(
        self,
        result: Dict[str, Any],
        query: str,
        operation_state: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate composite score for a result

        Args:
            result: Result dictionary
            query: Original query
            operation_state: Current operation state

        Returns:
            Composite score (0.0 to 1.0)
        """
        scores = {}

        # 1. Relevance score (from vector similarity or default)
        scores["relevance"] = result.get("similarity", result.get("score", 0.5))

        # 2. Severity score (for vulnerabilities)
        scores["severity"] = self._calculate_severity_score(result)

        # 3. Recency score
        scores["recency"] = self._calculate_recency_score(result)

        # 4. Success rate score (from historical data)
        scores["success_rate"] = self._calculate_success_rate_score(result)

        # 5. Phase alignment score
        scores["phase_alignment"] = self._calculate_phase_alignment_score(
            result,
            operation_state
        )

        # Calculate weighted composite score
        composite_score = sum(
            scores.get(factor, 0.0) * weight
            for factor, weight in self.weights.items()
        )

        return composite_score

    def _calculate_severity_score(self, result: Dict[str, Any]) -> float:
        """
        Calculate severity score for vulnerability results

        Args:
            result: Result dictionary

        Returns:
            Score from 0.0 to 1.0
        """
        # Check for CVE severity
        severity = result.get("severity", result.get("cvss_score"))

        if severity is None:
            return 0.5  # Neutral score

        # If it's a CVSS score (0-10)
        if isinstance(severity, (int, float)):
            return min(severity / 10.0, 1.0)

        # If it's a severity level
        severity_mapping = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "informational": 0.1,
        }

        return severity_mapping.get(str(severity).lower(), 0.5)

    def _calculate_recency_score(self, result: Dict[str, Any]) -> float:
        """
        Calculate recency score

        Args:
            result: Result dictionary

        Returns:
            Score from 0.0 to 1.0 (1.0 = most recent)
        """
        # Check for various date fields
        date_str = result.get("published_date") or result.get("updated_at") or result.get("created_at")

        if not date_str:
            return 0.5  # Neutral score

        try:
            if isinstance(date_str, datetime):
                date = date_str
            else:
                # Try to parse date string
                date = self._parse_date(date_str)

            if date:
                # Calculate age in days
                age_days = (datetime.now() - date).days

                # Exponential decay: more recent = higher score
                # Score drops to 0.5 after 365 days, 0.1 after 3 years
                return max(0.1, 1.0 * (0.9 ** (age_days / 365)))

        except Exception as e:
            self.logger.debug(f"Failed to parse date: {e}")

        return 0.5

    def _calculate_success_rate_score(self, result: Dict[str, Any]) -> float:
        """
        Calculate success rate score from historical data

        Args:
            result: Result dictionary

        Returns:
            Score from 0.0 to 1.0
        """
        success_rate = result.get("success_rate") or result.get("reliability")

        if success_rate is None:
            return 0.5  # Neutral score

        if isinstance(success_rate, (int, float)):
            return min(max(success_rate, 0.0), 1.0)

        return 0.5

    def _calculate_phase_alignment_score(
        self,
        result: Dict[str, Any],
        operation_state: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate how well the result aligns with current operation phase

        Args:
            result: Result dictionary
            operation_state: Current operation state

        Returns:
            Score from 0.0 to 1.0
        """
        if not operation_state:
            return 0.5

        current_phase = operation_state.get("phase", "").lower()

        # MITRE ATT&CK phase alignment
        result_tactics = result.get("tactics", [])
        if isinstance(result_tactics, str):
            result_tactics = [result_tactics]

        phase_mapping = {
            "reconnaissance": ["reconnaissance", "resource development"],
            "vulnerability_analysis": ["initial access", "execution"],
            "exploitation": ["privilege escalation", "defense evasion", "credential access"],
            "post_exploitation": ["discovery", "lateral movement", "collection"],
            "reporting": ["exfiltration", "impact"],
        }

        expected_tactics = phase_mapping.get(current_phase, [])

        if not result_tactics or not expected_tactics:
            return 0.5

        # Check overlap
        overlap = len(set(t.lower() for t in result_tactics) & set(expected_tactics))
        max_overlap = len(expected_tactics)

        return overlap / max_overlap if max_overlap > 0 else 0.5

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string in various formats"""
        formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%d/%m/%Y",
            "%m/%d/%Y",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        return None

    def set_weights(self, weights: Dict[str, float]):
        """
        Set custom weights for ranking factors

        Args:
            weights: Dictionary of factor weights (should sum to 1.0)
        """
        total_weight = sum(weights.values())
        if abs(total_weight - 1.0) > 0.01:
            self.logger.warning(
                f"Weights sum to {total_weight}, not 1.0. Normalizing..."
            )
            weights = {k: v / total_weight for k, v in weights.items()}

        self.weights.update(weights)
        self.logger.info(f"Updated ranking weights: {self.weights}")

    def filter_by_threshold(
        self,
        results: List[Dict[str, Any]],
        min_score: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Filter results by minimum score threshold

        Args:
            results: List of results (must have _rerank_score)
            min_score: Minimum score threshold

        Returns:
            Filtered results
        """
        return [
            result for result in results
            if result.get("_rerank_score", 0.0) >= min_score
        ]

    def diversify_results(
        self,
        results: List[Dict[str, Any]],
        diversity_factor: float = 0.5,
        max_similar: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Diversify results to avoid redundancy

        Args:
            results: List of ranked results
            diversity_factor: How much to prioritize diversity (0.0 to 1.0)
            max_similar: Maximum number of similar results

        Returns:
            Diversified results
        """
        if not results or diversity_factor == 0:
            return results

        diversified = []
        seen_types = {}

        for result in results:
            result_type = result.get("type", "unknown")

            # Count how many of this type we've seen
            count = seen_types.get(result_type, 0)

            if count < max_similar:
                diversified.append(result)
                seen_types[result_type] = count + 1
            elif len(diversified) < len(results):
                # Add with reduced priority
                if len(diversified) < len(results) * (1 + diversity_factor):
                    diversified.append(result)

        return diversified
