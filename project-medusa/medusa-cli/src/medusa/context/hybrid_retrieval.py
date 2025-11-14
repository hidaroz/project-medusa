"""
Hybrid Retrieval Strategy
Combines Vector DB and Graph DB retrieval intelligently
"""

from typing import Dict, Any, List, Optional
import asyncio
import logging


class HybridRetrieval:
    """
    Hybrid retrieval combining Vector and Graph databases

    Strategy:
    1. Determine optimal retrieval sources based on query
    2. Execute parallel queries
    3. Fuse and re-rank results
    4. Return unified context
    """

    def __init__(
        self,
        vector_store=None,
        graph_client=None,
        reranker=None,
        default_vector_weight: float = 0.6,
        default_graph_weight: float = 0.4
    ):
        """
        Initialize Hybrid Retrieval

        Args:
            vector_store: Vector database client
            graph_client: Graph database client
            reranker: Context reranker
            default_vector_weight: Default weight for vector results
            default_graph_weight: Default weight for graph results
        """
        self.vector_store = vector_store
        self.graph_client = graph_client
        self.reranker = reranker
        self.default_vector_weight = default_vector_weight
        self.default_graph_weight = default_graph_weight
        self.logger = logging.getLogger(__name__)

    async def retrieve(
        self,
        query: str,
        query_type: str = "hybrid",
        top_k: int = 5,
        min_score: float = 0.7,
        vector_weight: Optional[float] = None,
        graph_weight: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Perform hybrid retrieval

        Args:
            query: Search query
            query_type: Type of query for routing
            top_k: Number of results to return
            min_score: Minimum relevance score
            vector_weight: Weight for vector results (optional)
            graph_weight: Weight for graph results (optional)

        Returns:
            Combined results dictionary
        """
        vector_weight = vector_weight or self.default_vector_weight
        graph_weight = graph_weight or self.default_graph_weight

        # Determine retrieval strategy
        use_vector = query_type in ["vulnerability", "tool_usage", "mitre", "historical", "hybrid"]
        use_graph = query_type in ["attack_path", "network_topology", "hybrid"]

        # Execute queries in parallel
        tasks = []
        if use_vector and self.vector_store:
            tasks.append(self._query_vector(query, top_k))
        if use_graph and self.graph_client:
            tasks.append(self._query_graph(query, top_k))

        if not tasks:
            self.logger.warning("No retrieval sources available")
            return {"results": [], "sources": []}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Separate vector and graph results
        vector_results = []
        graph_results = []

        idx = 0
        if use_vector and self.vector_store:
            if not isinstance(results[idx], Exception):
                vector_results = results[idx]
            idx += 1

        if use_graph and self.graph_client:
            if not isinstance(results[idx], Exception):
                graph_results = results[idx]

        # Fuse results
        fused_results = self._fuse_results(
            vector_results,
            graph_results,
            vector_weight,
            graph_weight
        )

        # Re-rank if reranker is available
        if self.reranker and fused_results:
            fused_results = self.reranker.rerank(fused_results, query, top_k=top_k)

        # Filter by minimum score
        filtered_results = [
            r for r in fused_results
            if r.get("_final_score", 0.0) >= min_score
        ]

        return {
            "results": filtered_results[:top_k],
            "sources": {
                "vector_count": len(vector_results),
                "graph_count": len(graph_results),
                "fused_count": len(fused_results),
                "filtered_count": len(filtered_results),
            },
            "weights": {
                "vector": vector_weight,
                "graph": graph_weight,
            }
        }

    async def _query_vector(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Query vector database"""
        if not self.vector_store:
            return []

        try:
            # Query multiple collections
            mitre_results = self.vector_store.search_mitre_techniques(query, n_results=top_k)
            cve_results = self.vector_store.search_cves(query, n_results=top_k)
            tool_results = self.vector_store.search_tool_usage(query, n_results=top_k)

            # Combine and mark source
            all_results = []

            for result in mitre_results:
                all_results.append({**result, "_source": "vector", "_collection": "mitre"})

            for result in cve_results:
                all_results.append({**result, "_source": "vector", "_collection": "cve"})

            for result in tool_results:
                all_results.append({**result, "_source": "vector", "_collection": "tools"})

            return all_results

        except Exception as e:
            self.logger.error(f"Vector query failed: {e}")
            return []

    async def _query_graph(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Query graph database"""
        if not self.graph_client:
            return []

        try:
            # Get relevant graph data
            hosts = self.graph_client.get_all_hosts(limit=top_k)

            # Convert to standard format
            results = []
            for host in hosts:
                results.append({
                    **host,
                    "_source": "graph",
                    "_type": "host",
                    "score": 0.5,  # Default score
                })

            return results

        except Exception as e:
            self.logger.error(f"Graph query failed: {e}")
            return []

    def _fuse_results(
        self,
        vector_results: List[Dict[str, Any]],
        graph_results: List[Dict[str, Any]],
        vector_weight: float,
        graph_weight: float
    ) -> List[Dict[str, Any]]:
        """
        Fuse results from vector and graph databases

        Args:
            vector_results: Results from vector DB
            graph_results: Results from graph DB
            vector_weight: Weight for vector results
            graph_weight: Weight for graph results

        Returns:
            Fused results list
        """
        fused = []

        # Add vector results with weighted scores
        for result in vector_results:
            original_score = result.get("similarity", result.get("score", 0.5))
            fused.append({
                **result,
                "_original_score": original_score,
                "_final_score": original_score * vector_weight
            })

        # Add graph results with weighted scores
        for result in graph_results:
            original_score = result.get("score", 0.5)
            fused.append({
                **result,
                "_original_score": original_score,
                "_final_score": original_score * graph_weight
            })

        # Sort by final score
        fused.sort(key=lambda x: x["_final_score"], reverse=True)

        return fused

    def set_weights(self, vector_weight: float, graph_weight: float):
        """
        Set retrieval weights

        Args:
            vector_weight: Weight for vector results (0.0 to 1.0)
            graph_weight: Weight for graph results (0.0 to 1.0)
        """
        total = vector_weight + graph_weight
        if abs(total - 1.0) > 0.01:
            self.logger.warning(f"Weights sum to {total}, normalizing...")
            vector_weight /= total
            graph_weight /= total

        self.default_vector_weight = vector_weight
        self.default_graph_weight = graph_weight

        self.logger.info(
            f"Updated retrieval weights: vector={vector_weight:.2f}, graph={graph_weight:.2f}"
        )
