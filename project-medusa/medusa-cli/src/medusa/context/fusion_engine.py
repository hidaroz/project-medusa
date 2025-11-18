"""
Context Fusion Engine

Main orchestrator for context-aware AI operations.
Combines vector search, graph queries, and intelligent reranking
to provide optimal context for each operation phase.
"""

from typing import List, Dict, Any, Optional
import asyncio
from datetime import datetime

from .vector_store import VectorStore
from .hybrid_retrieval import HybridRetrieval
from .rag_optimizer import RAGOptimizer
from .reranker import ContextReranker


class ContextFusionEngine:
    """
    Main context fusion engine.

    Responsibilities:
    - Orchestrate hybrid retrieval
    - Build phase-specific context
    - Record operation history
    - Optimize context for LLM consumption
    """

    def __init__(
        self,
        vector_store: VectorStore,
        world_model: Any
    ):
        """
        Initialize context fusion engine.

        Args:
            vector_store: Vector database
            world_model: World Model client
        """
        self.vector_store = vector_store
        self.world_model = world_model
        self.hybrid_retrieval = HybridRetrieval(vector_store, world_model)
        self.rag_optimizer = RAGOptimizer(vector_store, world_model)
        self.reranker = ContextReranker()

        # Operation state tracking
        self.current_operation = None
        self.action_history = []

    def build_context_for_reconnaissance(
        self,
        target: str,
        existing_findings: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build context for reconnaissance phase.

        Returns:
        - Recommended MITRE techniques
        - Tool suggestions
        - Known infrastructure (from graph)
        """
        context = {
            'target': target,
            'phase': 'reconnaissance',
            'recommended_techniques': [],
            'tool_suggestions': [],
            'known_infrastructure': {}
        }

        # Get MITRE reconnaissance techniques
        mitre_results = self.vector_store.search_mitre_techniques(
            "reconnaissance enumeration discovery",
            tactic="reconnaissance",
            n_results=5
        )
        context['recommended_techniques'] = [
            {
                'technique_id': r.get('technique_id', 'T????'),
                'name': r.get('name', 'Unknown'),
                'description': r.get('description', '')
            }
            for r in mitre_results
        ]

        # Get tool suggestions
        tool_results = self.vector_store.search_tools(
            "reconnaissance scanning enumeration",
            tool_type="recon",
            n_results=5
        )
        context['tool_suggestions'] = [
            {
                'tool': r.get('tool_name', 'Unknown'),
                'usage': r.get('usage', ''),
                'description': r.get('description', '')
            }
            for r in tool_results
        ]

        # Get known infrastructure from graph
        try:
            hosts = self.world_model.get_all_hosts(limit=10)
            domains = self.world_model.get_all_domains(limit=5)
            context['known_infrastructure'] = {
                'hosts': len(hosts),
                'domains': len(domains)
            }
        except Exception:
            context['known_infrastructure'] = {'hosts': 0, 'domains': 0}

        return context

    def build_context_for_vulnerability_analysis(
        self,
        findings: List[Dict[str, Any]],
        target: str
    ) -> Dict[str, Any]:
        """
        Build context for vulnerability analysis phase.

        Returns:
        - Relevant CVEs
        - Exploitation techniques
        - Similar vulnerabilities
        """
        context = {
            'target': target,
            'phase': 'vulnerability_analysis',
            'relevant_cves': [],
            'exploitation_techniques': []
        }

        # Build search query from findings
        services = [
            f"{f.get('service', '')} {f.get('version', '')}"
            for f in findings
        ]
        search_query = " ".join(services)

        # Search for relevant CVEs
        cve_results = self.vector_store.search_cve(
            search_query,
            n_results=10
        )

        # Rerank CVEs by severity and recency
        reranked_cves = self.reranker.rerank(
            cve_results,
            operation_phase='vulnerability_analysis'
        )

        context['relevant_cves'] = [
            {
                'cve_id': r.get('cve_id', 'CVE-YYYY-XXXX'),
                'severity': r.get('severity', 'unknown'),
                'cvss': r.get('cvss', 0.0),
                'description': r.get('description', ''),
                'score': r.get('_final_score', 0.0)
            }
            for r in reranked_cves[:5]
        ]

        # Get exploitation techniques
        exploit_query = f"exploitation {search_query}"
        exploit_results = self.vector_store.search_mitre_techniques(
            exploit_query,
            tactic="execution",
            n_results=5
        )

        context['exploitation_techniques'] = [
            {
                'technique_id': r.get('technique_id', 'T????'),
                'name': r.get('name', 'Unknown'),
                'description': r.get('description', '')
            }
            for r in exploit_results
        ]

        return context

    def build_context_for_planning(
        self,
        all_findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """
        Build context for planning phase.

        Returns:
        - Attack chain templates
        - Similar past operations
        - Strategic recommendations
        """
        context = {
            'phase': 'planning',
            'attack_chain_templates': [],
            'similar_past_operations': []
        }

        # Search for similar past operations
        objectives_str = " ".join(objectives)
        past_ops = self.vector_store.search_operation_history(
            objectives_str,
            success_only=True,
            n_results=5
        )

        context['similar_past_operations'] = [
            {
                'operation_id': op.get('operation_id', 'unknown'),
                'techniques_used': op.get('techniques_used', []),
                'findings': op.get('findings_summary', ''),
                'success': op.get('success', False)
            }
            for op in past_ops
        ]

        # Get attack chain templates (MITRE sequences)
        attack_chain_results = self.vector_store.search_mitre_techniques(
            "lateral movement privilege escalation",
            n_results=5
        )

        context['attack_chain_templates'] = [
            {
                'technique_id': r.get('technique_id', 'T????'),
                'name': r.get('name', 'Unknown'),
                'tactic': r.get('tactic', 'unknown')
            }
            for r in attack_chain_results
        ]

        return context

    async def get_contextual_recommendations(
        self,
        query: str,
        operation_phase: str,
        operation_state: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get context-aware recommendations for current operation.

        Args:
            query: User query or task description
            operation_phase: Current phase (reconnaissance, analysis, etc.)
            operation_state: Current operation state

        Returns:
            Ranked recommendations with context
        """
        # Use RAG optimizer for retrieval
        results = await self.rag_optimizer.retrieve(
            query,
            n_results=10,
            operation_state=operation_state
        )

        # Rerank for current phase
        reranked = self.reranker.rerank(
            results,
            operation_phase=operation_phase,
            query=query,
            context=operation_state
        )

        return reranked[:5]

    def record_action(self, action: Dict[str, Any]):
        """Record an action for operation history."""
        action['timestamp'] = datetime.now().isoformat()
        self.action_history.append(action)

    async def add_operation_to_history(
        self,
        operation_id: str,
        target: str,
        objectives: List[str],
        findings_summary: str,
        techniques_used: List[str],
        success: bool,
        duration_seconds: float
    ):
        """
        Add completed operation to history for future reference.

        Args:
            operation_id: Unique operation identifier
            target: Target of operation
            objectives: Operation objectives
            findings_summary: Summary of findings
            techniques_used: MITRE techniques used
            success: Whether operation succeeded
            duration_seconds: Operation duration
        """
        operation_doc = {
            'id': f"operation_{operation_id}",
            'operation_id': operation_id,
            'content': f"{' '.join(objectives)} against {target}: {findings_summary}",
            'target': target,
            'objectives': objectives,
            'findings_summary': findings_summary,
            'techniques_used': techniques_used,
            'success': success,
            'duration_seconds': duration_seconds,
            'timestamp': datetime.now().isoformat()
        }

        # Add to vector store
        self.vector_store.add_documents(
            'operations',
            [operation_doc]
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            'vector_store': self.vector_store.get_stats(),
            'rag_optimizer': self.rag_optimizer.get_metrics(),
            'actions_recorded': len(self.action_history)
        }
