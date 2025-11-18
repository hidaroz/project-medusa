"""
RAG Optimizer

Optimizes retrieval-augmented generation by:
- Classifying query types
- Selecting optimal retrieval strategies
- Caching frequently accessed context
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import hashlib
from .vector_store import VectorStore
from .hybrid_retrieval import HybridRetrieval


class QueryType(str, Enum):
    """Types of queries for retrieval optimization."""
    VULNERABILITY = "vulnerability"
    MITRE_TECHNIQUE = "mitre"
    TOOL_USAGE = "tool_usage"
    ATTACK_PATH = "attack_path"
    OPERATION_HISTORY = "operation_history"
    GENERAL = "general"


class RAGOptimizer:
    """
    Optimizes RAG retrieval with query classification and caching.

    Features:
    - Automatic query type classification
    - Cache for frequently accessed context
    - Adaptive retrieval strategies
    """

    def __init__(self, vector_store: VectorStore, world_model: Any):
        """
        Initialize RAG optimizer.

        Args:
            vector_store: Vector database
            world_model: World Model client
        """
        self.vector_store = vector_store
        self.world_model = world_model
        self.hybrid_retrieval = HybridRetrieval(vector_store, world_model)

        # Cache configuration
        self.cache = {}
        self.cache_ttl = timedelta(minutes=30)
        self.cache_hits = 0
        self.cache_misses = 0

        # Query type statistics
        self.query_type_counts = {qt: 0 for qt in QueryType}

    def _classify_query(
        self,
        query: str,
        operation_state: Optional[Dict[str, Any]] = None
    ) -> QueryType:
        """
        Classify query type for optimal retrieval.

        Args:
            query: User query
            operation_state: Current operation context

        Returns:
            Classified query type
        """
        query_lower = query.lower()

        # CVE/Vulnerability keywords
        if any(kw in query_lower for kw in [
            'cve', 'vulnerability', 'vuln', 'exploit', 'rce', 'xss',
            'sql injection', 'buffer overflow', 'patch'
        ]):
            return QueryType.VULNERABILITY

        # MITRE ATT&CK keywords
        if any(kw in query_lower for kw in [
            'mitre', 'att&ck', 'tactic', 'technique', 't1', 'ta0'
        ]):
            return QueryType.MITRE_TECHNIQUE

        # Tool usage keywords
        if any(kw in query_lower for kw in [
            'nmap', 'metasploit', 'burp', 'sqlmap', 'command',
            'how to', 'scan', 'enumerate'
        ]):
            return QueryType.TOOL_USAGE

        # Attack path keywords
        if any(kw in query_lower for kw in [
            'path', 'from', 'to', 'pivot', 'lateral movement',
            'route', 'chain'
        ]):
            return QueryType.ATTACK_PATH

        # Operation history keywords
        if any(kw in query_lower for kw in [
            'similar', 'previous', 'past', 'history', 'before',
            'last time'
        ]):
            return QueryType.OPERATION_HISTORY

        return QueryType.GENERAL

    def _get_cache_key(self, query: str, query_type: QueryType) -> str:
        """Generate cache key for query."""
        content = f"{query}:{query_type.value}"
        return hashlib.md5(content.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieve results from cache if valid."""
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            timestamp = cached_data['timestamp']
            if datetime.now() - timestamp < self.cache_ttl:
                self.cache_hits += 1
                return cached_data['results']
            else:
                # Cache expired
                del self.cache[cache_key]

        self.cache_misses += 1
        return None

    def _add_to_cache(
        self,
        cache_key: str,
        results: List[Dict[str, Any]]
    ):
        """Add results to cache."""
        self.cache[cache_key] = {
            'results': results,
            'timestamp': datetime.now()
        }

    async def retrieve(
        self,
        query: str,
        n_results: int = 5,
        operation_state: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Optimized retrieval with classification and caching.

        Args:
            query: Search query
            n_results: Number of results to return
            operation_state: Current operation context

        Returns:
            Retrieved and optimized results
        """
        # Classify query
        query_type = self._classify_query(query, operation_state)
        self.query_type_counts[query_type] += 1

        # Check cache
        cache_key = self._get_cache_key(query, query_type)
        cached_results = self._get_from_cache(cache_key)
        if cached_results:
            return cached_results[:n_results]

        # Select retrieval strategy based on query type
        if query_type == QueryType.VULNERABILITY:
            results = self.vector_store.search_cve(query, n_results=n_results)
            # Enhance with vector store metadata
            for result in results:
                result['_source'] = 'vector:cve'
                result['_final_score'] = result.get('relevance_score', 0.0)

        elif query_type == QueryType.MITRE_TECHNIQUE:
            results = self.vector_store.search_mitre_techniques(
                query,
                n_results=n_results
            )
            for result in results:
                result['_source'] = 'vector:mitre'
                result['_final_score'] = result.get('relevance_score', 0.0)

        elif query_type == QueryType.TOOL_USAGE:
            results = self.vector_store.search_tools(query, n_results=n_results)
            for result in results:
                result['_source'] = 'vector:tools'
                result['_final_score'] = result.get('relevance_score', 0.0)

        elif query_type == QueryType.ATTACK_PATH:
            results = await self.hybrid_retrieval.retrieve(
                query,
                query_type="attack_path",
                n_results=n_results,
                context=operation_state
            )

        elif query_type == QueryType.OPERATION_HISTORY:
            results = self.vector_store.search_operation_history(
                query,
                n_results=n_results
            )
            for result in results:
                result['_source'] = 'vector:operations'
                result['_final_score'] = result.get('relevance_score', 0.0)

        else:  # GENERAL
            results = await self.hybrid_retrieval.retrieve(
                query,
                query_type="hybrid",
                n_results=n_results,
                context=operation_state
            )

        # Cache results
        self._add_to_cache(cache_key, results)

        return results

    def get_metrics(self) -> Dict[str, Any]:
        """Get optimizer performance metrics."""
        total_queries = self.cache_hits + self.cache_misses
        hit_rate = (
            self.cache_hits / total_queries if total_queries > 0 else 0
        )

        return {
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'hit_rate': hit_rate,
            'cache_size': len(self.cache),
            'query_types': {
                qt.value: count
                for qt, count in self.query_type_counts.items()
                if count > 0
            }
        }

    def clear_cache(self):
        """Clear the cache."""
        self.cache.clear()
        self.cache_hits = 0
        self.cache_misses = 0
