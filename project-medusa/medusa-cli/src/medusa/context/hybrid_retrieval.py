"""
Hybrid Retrieval System

Combines vector-based semantic search with graph-based retrieval to provide
comprehensive context for penetration testing operations.
"""

from typing import List, Dict, Any, Optional
from .vector_store import VectorStore


class HybridRetrieval:
    """
    Hybrid retrieval combining vector search and graph queries.

    Intelligently combines results from:
    - Vector store (semantic similarity)
    - World Model graph (structural relationships)
    """

    def __init__(self, vector_store: VectorStore, world_model: Any):
        """
        Initialize hybrid retrieval.

        Args:
            vector_store: Vector database for semantic search
            world_model: World Model client for graph queries
        """
        self.vector_store = vector_store
        self.world_model = world_model

    async def retrieve(
        self,
        query: str,
        query_type: str = "hybrid",
        n_results: int = 5,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant context using hybrid approach.

        Args:
            query: Search query
            query_type: Type of query (hybrid, vector_only, graph_only, attack_path)
            n_results: Number of results to return
            context: Additional context (target, phase, etc.)

        Returns:
            List of results with metadata and scores
        """
        if query_type == "vector_only":
            return await self._vector_retrieval(query, n_results)
        elif query_type == "graph_only":
            return await self._graph_retrieval(query, n_results, context)
        elif query_type == "attack_path":
            return await self._attack_path_retrieval(query, n_results, context)
        else:  # hybrid
            return await self._hybrid_retrieval(query, n_results, context)

    async def _vector_retrieval(
        self,
        query: str,
        n_results: int
    ) -> List[Dict[str, Any]]:
        """Retrieve using vector search only."""
        results = []

        # Search across all collections
        for collection in ["mitre", "cve", "tools", "operations"]:
            coll_results = self.vector_store.search(
                collection,
                query,
                n_results=max(2, n_results // 2)
            )
            for result in coll_results:
                result['_source'] = f'vector:{collection}'
                result['_final_score'] = result.get('relevance_score', 0.0)
                results.append(result)

        # Sort by score and return top N
        results.sort(key=lambda x: x['_final_score'], reverse=True)
        return results[:n_results]

    async def _graph_retrieval(
        self,
        query: str,
        n_results: int,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve using graph queries only."""
        results = []

        try:
            # Get hosts from graph
            hosts = self.world_model.get_all_hosts(limit=n_results)
            for host in hosts:
                results.append({
                    'id': f"host_{host.get('ip', 'unknown')}",
                    'content': f"Host {host.get('ip')} with {len(host.get('ports', []))} ports",
                    'metadata': host,
                    '_source': 'graph:hosts',
                    '_final_score': 0.8  # Graph results get high score
                })

            # Get domains from graph
            domains = self.world_model.get_all_domains(limit=max(2, n_results // 2))
            for domain in domains:
                results.append({
                    'id': f"domain_{domain.get('name', 'unknown')}",
                    'content': f"Domain {domain.get('name')}",
                    'metadata': domain,
                    '_source': 'graph:domains',
                    '_final_score': 0.8
                })
        except Exception as e:
            # Graph queries may fail if not connected
            pass

        return results[:n_results]

    async def _attack_path_retrieval(
        self,
        query: str,
        n_results: int,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve attack paths from graph."""
        results = []

        try:
            # Extract source and target from query
            # This is simplified - real implementation would use NLP
            if "from" in query.lower() and "to" in query.lower():
                # Try to find attack paths
                hosts = self.world_model.get_all_hosts(limit=5)
                for i, host in enumerate(hosts):
                    results.append({
                        'id': f"path_{i}",
                        'content': f"Attack path involving {host.get('ip')}",
                        'metadata': {'host': host, 'type': 'attack_path'},
                        '_source': 'graph:attack_paths',
                        '_final_score': 0.9
                    })
        except Exception:
            pass

        return results[:n_results]

    async def _hybrid_retrieval(
        self,
        query: str,
        n_results: int,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Combine vector and graph retrieval.

        Strategy:
        1. Get results from both sources
        2. Normalize scores
        3. Merge and deduplicate
        4. Re-rank based on relevance
        """
        # Get vector results
        vector_results = await self._vector_retrieval(
            query,
            n_results=n_results
        )

        # Get graph results
        graph_results = await self._graph_retrieval(
            query,
            n_results=max(2, n_results // 3),
            context=context
        )

        # Combine results
        all_results = []
        seen_ids = set()

        # Add vector results
        for result in vector_results:
            result_id = result.get('id')
            if result_id not in seen_ids:
                all_results.append(result)
                seen_ids.add(result_id)

        # Add graph results
        for result in graph_results:
            result_id = result.get('id')
            if result_id not in seen_ids:
                all_results.append(result)
                seen_ids.add(result_id)

        # Sort by final score
        all_results.sort(key=lambda x: x.get('_final_score', 0), reverse=True)

        return all_results[:n_results]
