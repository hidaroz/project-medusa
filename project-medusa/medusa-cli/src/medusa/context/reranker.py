"""
Context Reranker

Reranks retrieved context based on multiple factors:
- Relevance score
- Recency
- Severity (for vulnerabilities)
- Operation phase
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta


class ContextReranker:
    """
    Reranks retrieved context for optimal relevance.

    Considers:
    - Base relevance score
    - Temporal relevance (recency)
    - Severity/importance (for CVEs)
    - Phase-specific boost (reconnaissance vs exploitation)
    """

    def __init__(self):
        """Initialize context reranker."""
        # Phase-specific boosting factors
        self.phase_boosts = {
            'reconnaissance': {
                'mitre': 1.3,  # Boost MITRE techniques
                'tools': 1.2,  # Boost tool documentation
                'operations': 1.1  # Slight boost to operation history
            },
            'vulnerability_analysis': {
                'cve': 1.4,  # Strong boost for CVEs
                'mitre': 1.1,
                'operations': 1.2
            },
            'exploitation': {
                'cve': 1.3,
                'tools': 1.2,
                'mitre': 1.1
            },
            'planning': {
                'operations': 1.4,  # Strong boost for past operations
                'mitre': 1.2,
                'tools': 1.1
            }
        }

    def rerank(
        self,
        results: List[Dict[str, Any]],
        operation_phase: Optional[str] = None,
        query: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Rerank results based on multiple factors.

        Args:
            results: Initial retrieval results
            operation_phase: Current operation phase
            query: Original query (for relevance adjustment)
            context: Additional context

        Returns:
            Reranked results with updated scores
        """
        reranked = []

        for result in results:
            score = result.get('relevance_score', 0.0)

            # Apply temporal boost (recency)
            score = self._apply_temporal_boost(result, score)

            # Apply severity boost (for CVEs)
            score = self._apply_severity_boost(result, score)

            # Apply phase-specific boost
            if operation_phase:
                score = self._apply_phase_boost(
                    result,
                    score,
                    operation_phase
                )

            # Apply source-specific adjustments
            score = self._apply_source_boost(result, score)

            # Update result with final score
            result['_final_score'] = score
            result['_original_score'] = result.get('relevance_score', 0.0)
            reranked.append(result)

        # Sort by final score
        reranked.sort(key=lambda x: x['_final_score'], reverse=True)

        return reranked

    def _apply_temporal_boost(
        self,
        result: Dict[str, Any],
        score: float
    ) -> float:
        """
        Boost score based on recency.

        Recent content (especially CVEs) gets higher scores.
        """
        timestamp_str = result.get('timestamp')
        if not timestamp_str:
            return score

        try:
            timestamp = datetime.fromisoformat(timestamp_str)
            age = datetime.now() - timestamp

            # Boost for content less than 1 year old
            if age < timedelta(days=365):
                boost_factor = 1.0 + (0.2 * (1 - age.days / 365))
                score *= boost_factor

        except Exception:
            pass

        return score

    def _apply_severity_boost(
        self,
        result: Dict[str, Any],
        score: float
    ) -> float:
        """
        Boost score based on severity (for vulnerabilities).

        Critical CVEs get highest boost.
        """
        severity = result.get('severity', '').lower()
        cvss = result.get('cvss', 0.0)

        if severity == 'critical' or cvss >= 9.0:
            score *= 1.5
        elif severity == 'high' or cvss >= 7.0:
            score *= 1.3
        elif severity == 'medium' or cvss >= 4.0:
            score *= 1.1

        return score

    def _apply_phase_boost(
        self,
        result: Dict[str, Any],
        score: float,
        phase: str
    ) -> float:
        """
        Apply phase-specific boosting.

        Different types of context are more relevant in different phases.
        """
        source = result.get('_source', '')

        # Extract collection name from source (e.g., "vector:cve" -> "cve")
        if ':' in source:
            collection = source.split(':')[1]
        else:
            collection = source

        # Get boost factor for this phase and collection
        phase_boost_map = self.phase_boosts.get(phase, {})
        boost_factor = phase_boost_map.get(collection, 1.0)

        return score * boost_factor

    def _apply_source_boost(
        self,
        result: Dict[str, Any],
        score: float
    ) -> float:
        """
        Apply source-specific adjustments.

        Graph data typically has higher confidence than vector similarity.
        """
        source = result.get('_source', '')

        # Graph sources get slight boost (more authoritative)
        if source.startswith('graph:'):
            score *= 1.1

        # Operation history that was successful gets boost
        if 'operations' in source and result.get('success'):
            score *= 1.2

        return score
