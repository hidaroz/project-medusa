"""
RAG System Optimizer
Optimizes RAG retrieval quality and performance
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
import asyncio
from enum import Enum
import numpy as np


class QueryType(Enum):
    """Types of queries for routing"""
    VULNERABILITY = "vulnerability"
    ATTACK_PATH = "attack_path"
    TOOL_USAGE = "tool_usage"
    MITRE_TECHNIQUE = "mitre_technique"
    HISTORICAL = "historical"
    NETWORK_TOPOLOGY = "network_topology"
    HYBRID = "hybrid"


class RAGOptimizer:
    """
    RAG System Optimizer

    Provides intelligent query routing, context fusion, and performance optimization
    """

    def __init__(
        self,
        world_model=None,
        vector_store=None,
        fusion_engine=None,
        cache_enabled: bool = True,
        cache_ttl: int = 3600,
    ):
        """
        Initialize RAG Optimizer

        Args:
            world_model: Neo4j world model client
            vector_store: Vector database client
            fusion_engine: Context fusion engine
            cache_enabled: Enable query caching
            cache_ttl: Cache time-to-live in seconds
        """
        self.world_model = world_model
        self.vector_store = vector_store
        self.fusion_engine = fusion_engine
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.logger = logging.getLogger(__name__)

        # Query cache
        self._query_cache: Dict[str, Tuple[Any, datetime]] = {}

        # Performance metrics
        self.metrics = {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_retrieval_time": 0.0,
            "vector_queries": 0,
            "graph_queries": 0,
            "hybrid_queries": 0,
        }

    async def get_optimized_context(
        self,
        query: str,
        operation_state: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
        min_score: float = 0.7,
    ) -> Dict[str, Any]:
        """
        Get optimized context for a query

        Args:
            query: User query
            operation_state: Current operation state
            top_k: Number of results to return
            min_score: Minimum relevance score

        Returns:
            Optimized context dictionary
        """
        start_time = datetime.now()
        self.metrics["total_queries"] += 1

        # Check cache first
        if self.cache_enabled:
            cached_result = self._check_cache(query)
            if cached_result:
                self.metrics["cache_hits"] += 1
                self.logger.debug(f"Cache hit for query: {query[:50]}...")
                return cached_result

        self.metrics["cache_misses"] += 1

        # 1. Classify query type
        query_type = self._classify_query(query, operation_state)
        self.logger.info(f"Query classified as: {query_type.value}")

        # 2. Route to appropriate retrieval strategy
        if query_type == QueryType.VULNERABILITY:
            context = await self._retrieve_vulnerability_context(query, top_k, min_score)
            self.metrics["vector_queries"] += 1

        elif query_type == QueryType.ATTACK_PATH:
            context = await self._retrieve_attack_path_context(query, top_k)
            self.metrics["graph_queries"] += 1

        elif query_type == QueryType.NETWORK_TOPOLOGY:
            context = await self._retrieve_topology_context(query)
            self.metrics["graph_queries"] += 1

        elif query_type == QueryType.TOOL_USAGE:
            context = await self._retrieve_tool_usage_context(query, top_k, min_score)
            self.metrics["vector_queries"] += 1

        elif query_type == QueryType.MITRE_TECHNIQUE:
            context = await self._retrieve_mitre_context(query, top_k, min_score)
            self.metrics["vector_queries"] += 1

        elif query_type == QueryType.HISTORICAL:
            context = await self._retrieve_historical_context(query, top_k, min_score)
            self.metrics["vector_queries"] += 1

        else:  # HYBRID
            context = await self._retrieve_hybrid_context(query, top_k, min_score)
            self.metrics["hybrid_queries"] += 1

        # 3. Enrich with operation state
        if operation_state:
            context = self._enrich_with_operation_state(context, operation_state)

        # 4. Add metadata
        retrieval_time = (datetime.now() - start_time).total_seconds()
        context["_metadata"] = {
            "query_type": query_type.value,
            "retrieval_time_ms": retrieval_time * 1000,
            "cached": False,
            "timestamp": datetime.now().isoformat(),
        }

        # Update metrics
        self._update_metrics(retrieval_time)

        # Cache result
        if self.cache_enabled:
            self._cache_result(query, context)

        return context

    def _classify_query(
        self,
        query: str,
        operation_state: Optional[Dict[str, Any]] = None
    ) -> QueryType:
        """
        Classify query to route to appropriate retrieval strategy

        Args:
            query: User query
            operation_state: Current operation state

        Returns:
            QueryType enum
        """
        query_lower = query.lower()

        # Keyword-based classification (can be enhanced with ML)
        if any(keyword in query_lower for keyword in ["cve", "vulnerability", "exploit", "vuln"]):
            return QueryType.VULNERABILITY

        if any(keyword in query_lower for keyword in ["path", "pivot", "lateral", "move from", "route to"]):
            return QueryType.ATTACK_PATH

        if any(keyword in query_lower for keyword in ["network", "topology", "connected", "hosts", "infrastructure"]):
            return QueryType.NETWORK_TOPOLOGY

        if any(keyword in query_lower for keyword in ["tool", "how to use", "command", "nmap", "scan"]):
            return QueryType.TOOL_USAGE

        if any(keyword in query_lower for keyword in ["mitre", "att&ck", "technique", "tactic"]):
            return QueryType.MITRE_TECHNIQUE

        if any(keyword in query_lower for keyword in ["previous", "history", "last time", "similar"]):
            return QueryType.HISTORICAL

        # Check operation state for context
        if operation_state:
            phase = operation_state.get("phase", "")
            if "exploit" in phase.lower():
                return QueryType.VULNERABILITY
            if "recon" in phase.lower():
                return QueryType.NETWORK_TOPOLOGY

        # Default to hybrid search
        return QueryType.HYBRID

    async def _retrieve_vulnerability_context(
        self,
        query: str,
        top_k: int,
        min_score: float
    ) -> Dict[str, Any]:
        """Retrieve vulnerability-related context"""
        if not self.vector_store:
            return {"vulnerabilities": [], "exploits": []}

        # Search CVE database
        cve_results = self.vector_store.search_cves(
            query=query,
            n_results=top_k
        )

        # Also check graph for known vulnerabilities
        graph_vulns = []
        if self.world_model:
            try:
                # Query for vulnerabilities in the graph
                graph_vulns = await self._async_graph_query(
                    "MATCH (v:Vulnerability) "
                    "RETURN v.cve_id as cve, v.severity as severity, v.description as description "
                    "LIMIT $limit",
                    {"limit": top_k}
                )
            except Exception as e:
                self.logger.warning(f"Graph vulnerability query failed: {e}")

        return {
            "type": "vulnerability",
            "cve_results": cve_results,
            "known_vulnerabilities": graph_vulns,
        }

    async def _retrieve_attack_path_context(
        self,
        query: str,
        top_k: int
    ) -> Dict[str, Any]:
        """Retrieve attack path context from graph"""
        if not self.world_model:
            return {"paths": []}

        try:
            # Extract source and target from query (simplified - can be enhanced)
            # For now, query the graph for possible paths
            paths = await self._async_graph_query(
                "MATCH path = (source:Host)-[*1..3]->(target:Host) "
                "RETURN path "
                "LIMIT $limit",
                {"limit": top_k}
            )

            return {
                "type": "attack_path",
                "paths": paths,
            }
        except Exception as e:
            self.logger.error(f"Attack path query failed: {e}")
            return {"type": "attack_path", "paths": []}

    async def _retrieve_topology_context(self, query: str) -> Dict[str, Any]:
        """Retrieve network topology context"""
        if not self.world_model:
            return {"hosts": [], "services": [], "relationships": []}

        try:
            hosts = self.world_model.get_all_hosts(limit=50)
            services = await self._async_graph_query(
                "MATCH (s:Service) RETURN s LIMIT 100"
            )

            return {
                "type": "network_topology",
                "hosts": hosts,
                "services": services,
            }
        except Exception as e:
            self.logger.error(f"Topology query failed: {e}")
            return {"type": "network_topology", "hosts": [], "services": []}

    async def _retrieve_tool_usage_context(
        self,
        query: str,
        top_k: int,
        min_score: float
    ) -> Dict[str, Any]:
        """Retrieve tool usage examples"""
        if not self.vector_store:
            return {"tool_examples": []}

        tool_examples = self.vector_store.search_tool_usage(
            query=query,
            n_results=top_k
        )

        return {
            "type": "tool_usage",
            "examples": tool_examples,
        }

    async def _retrieve_mitre_context(
        self,
        query: str,
        top_k: int,
        min_score: float
    ) -> Dict[str, Any]:
        """Retrieve MITRE ATT&CK techniques"""
        if not self.vector_store:
            return {"techniques": []}

        techniques = self.vector_store.search_mitre_techniques(
            query=query,
            n_results=top_k
        )

        return {
            "type": "mitre",
            "techniques": techniques,
        }

    async def _retrieve_historical_context(
        self,
        query: str,
        top_k: int,
        min_score: float
    ) -> Dict[str, Any]:
        """Retrieve historical operation context"""
        if not self.vector_store:
            return {"history": []}

        history = self.vector_store.search_operation_history(
            query=query,
            n_results=top_k
        )

        return {
            "type": "historical",
            "history": history,
        }

    async def _retrieve_hybrid_context(
        self,
        query: str,
        top_k: int,
        min_score: float
    ) -> Dict[str, Any]:
        """Retrieve context from both vector and graph databases"""
        # Run vector and graph queries in parallel
        vector_task = self._retrieve_vector_context(query, top_k, min_score)
        graph_task = self._retrieve_graph_context(query, top_k)

        vector_results, graph_results = await asyncio.gather(
            vector_task,
            graph_task,
            return_exceptions=True
        )

        # Handle exceptions
        if isinstance(vector_results, Exception):
            self.logger.error(f"Vector search failed: {vector_results}")
            vector_results = {}

        if isinstance(graph_results, Exception):
            self.logger.error(f"Graph search failed: {graph_results}")
            graph_results = {}

        # Fuse results
        fused_context = self._fuse_contexts(vector_results, graph_results)

        return {
            "type": "hybrid",
            **fused_context
        }

    async def _retrieve_vector_context(
        self,
        query: str,
        top_k: int,
        min_score: float
    ) -> Dict[str, Any]:
        """Retrieve from vector database"""
        if not self.vector_store:
            return {}

        # Search across all vector collections
        results = {
            "mitre": self.vector_store.search_mitre_techniques(query, n_results=top_k),
            "cves": self.vector_store.search_cves(query, n_results=top_k),
            "tools": self.vector_store.search_tool_usage(query, n_results=top_k),
        }

        return results

    async def _retrieve_graph_context(
        self,
        query: str,
        top_k: int
    ) -> Dict[str, Any]:
        """Retrieve from graph database"""
        if not self.world_model:
            return {}

        try:
            hosts = self.world_model.get_all_hosts(limit=top_k)
            return {"hosts": hosts}
        except Exception as e:
            self.logger.error(f"Graph query failed: {e}")
            return {}

    def _fuse_contexts(
        self,
        vector_results: Dict[str, Any],
        graph_results: Dict[str, Any],
        vector_weight: float = 0.6,
        graph_weight: float = 0.4
    ) -> Dict[str, Any]:
        """
        Fuse vector and graph results

        Args:
            vector_results: Results from vector database
            graph_results: Results from graph database
            vector_weight: Weight for vector results
            graph_weight: Weight for graph results

        Returns:
            Fused context
        """
        return {
            "vector_results": vector_results,
            "graph_results": graph_results,
            "weights": {
                "vector": vector_weight,
                "graph": graph_weight,
            }
        }

    def _enrich_with_operation_state(
        self,
        context: Dict[str, Any],
        operation_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich context with current operation state"""
        context["operation_state"] = {
            "phase": operation_state.get("phase"),
            "target": operation_state.get("target"),
            "findings_count": len(operation_state.get("findings", [])),
        }
        return context

    async def _async_graph_query(self, query: str, params: Optional[Dict] = None):
        """Execute graph query asynchronously"""
        # Placeholder - implement actual async graph query
        return []

    def _check_cache(self, query: str) -> Optional[Dict[str, Any]]:
        """Check if query result is cached"""
        if query in self._query_cache:
            result, timestamp = self._query_cache[query]
            if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                return result

        return None

    def _cache_result(self, query: str, result: Dict[str, Any]):
        """Cache query result"""
        self._query_cache[query] = (result, datetime.now())

        # Cleanup old cache entries
        if len(self._query_cache) > 1000:
            self._cleanup_cache()

    def _cleanup_cache(self):
        """Remove expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, (_, timestamp) in self._query_cache.items()
            if now - timestamp >= timedelta(seconds=self.cache_ttl)
        ]

        for key in expired_keys:
            del self._query_cache[key]

        self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

    def _update_metrics(self, retrieval_time: float):
        """Update performance metrics"""
        # Update average retrieval time (exponential moving average)
        alpha = 0.1  # Smoothing factor
        if self.metrics["avg_retrieval_time"] == 0:
            self.metrics["avg_retrieval_time"] = retrieval_time
        else:
            self.metrics["avg_retrieval_time"] = (
                alpha * retrieval_time +
                (1 - alpha) * self.metrics["avg_retrieval_time"]
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        cache_hit_rate = (
            self.metrics["cache_hits"] / self.metrics["total_queries"]
            if self.metrics["total_queries"] > 0
            else 0.0
        )

        return {
            **self.metrics,
            "cache_hit_rate": cache_hit_rate,
            "avg_retrieval_time_ms": self.metrics["avg_retrieval_time"] * 1000,
        }

    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = {
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_retrieval_time": 0.0,
            "vector_queries": 0,
            "graph_queries": 0,
            "hybrid_queries": 0,
        }

    def clear_cache(self):
        """Clear query cache"""
        self._query_cache.clear()
        self.logger.info("Query cache cleared")
