"""
Context Fusion Engine
Combines Neo4j graph data with vector DB semantic search
to build rich, intelligent context for LLM prompts
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import json


class ContextFusionEngine:
    """
    Fuses multiple knowledge sources into unified LLM context

    Sources:
    1. Neo4j Graph - Current infrastructure state, relationships
    2. Vector DB - Semantic knowledge (MITRE, CVEs, tool docs)
    3. Operation History - Short-term memory of current session
    """

    def __init__(
        self,
        world_model: Optional['WorldModelClient'] = None,
        vector_store: Optional['VectorStore'] = None
    ):
        """
        Initialize Context Fusion Engine

        Args:
            world_model: Neo4j world model client
            vector_store: ChromaDB vector store
        """
        self.world_model = world_model
        self.vector_store = vector_store
        self.logger = logging.getLogger(__name__)

        # Short-term memory: current operation history
        self.operation_history: List[Dict[str, Any]] = []

    def build_context_for_reconnaissance(
        self,
        target: str,
        existing_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Build context for reconnaissance phase

        Args:
            target: Target URL/IP
            existing_findings: Already discovered findings

        Returns:
            Rich context dict with graph state, MITRE techniques, tool suggestions
        """
        context = {
            "phase": "reconnaissance",
            "target": target
        }

        # 1. Graph: Check what we already know about this target
        if self.world_model:
            try:
                existing_hosts = self.world_model.get_all_hosts(limit=10)
                context["known_infrastructure"] = {
                    "host_count": len(existing_hosts),
                    "hosts": existing_hosts[:5]  # Top 5
                }
            except Exception as e:
                self.logger.warning(f"Failed to get graph data: {e}")
                context["known_infrastructure"] = {"host_count": 0, "hosts": []}
        else:
            context["known_infrastructure"] = {"host_count": 0, "hosts": []}

        # 2. Vector: Relevant MITRE techniques for reconnaissance
        if self.vector_store:
            try:
                mitre_techniques = self.vector_store.search_mitre_techniques(
                    query="network reconnaissance port scanning service discovery",
                    n_results=5
                )
                context["recommended_techniques"] = mitre_techniques
            except Exception as e:
                self.logger.warning(f"Failed to search MITRE techniques: {e}")
                context["recommended_techniques"] = []
        else:
            context["recommended_techniques"] = []

        # 3. Vector: Tool usage examples
        if self.vector_store:
            try:
                tool_suggestions = self.vector_store.search_tool_usage(
                    query="network port scanning service enumeration",
                    n_results=3
                )
                context["tool_suggestions"] = tool_suggestions
            except Exception as e:
                self.logger.warning(f"Failed to search tool usage: {e}")
                context["tool_suggestions"] = []
        else:
            context["tool_suggestions"] = []

        # 4. Operation history
        context["recent_actions"] = self.operation_history[-5:] if self.operation_history else []

        self.logger.info(
            f"Context built for reconnaissance: "
            f"{len(context.get('recommended_techniques', []))} MITRE techniques, "
            f"{len(context.get('tool_suggestions', []))} tool suggestions"
        )

        return context

    def build_context_for_vulnerability_analysis(
        self,
        findings: List[Dict[str, Any]],
        target: str
    ) -> Dict[str, Any]:
        """
        Build context for vulnerability analysis phase

        Args:
            findings: Discovered findings from reconnaissance
            target: Target URL/IP

        Returns:
            Context with known vulns, CVEs, and exploitation techniques
        """
        context = {
            "phase": "vulnerability_analysis",
            "target": target,
            "findings_count": len(findings)
        }

        # 1. Graph: Get current vulnerabilities and relationships
        if self.world_model:
            try:
                known_vulns = self.world_model.get_vulnerabilities()
                context["known_vulnerabilities"] = {
                    "count": len(known_vulns),
                    "high_severity": [v for v in known_vulns if v.get("severity") == "high"]
                }
            except Exception as e:
                self.logger.warning(f"Failed to get vulnerabilities from graph: {e}")
                context["known_vulnerabilities"] = {"count": 0, "high_severity": []}
        else:
            context["known_vulnerabilities"] = {"count": 0, "high_severity": []}

        # 2. Extract unique services from findings
        services = set()
        for finding in findings:
            if finding.get("type") == "open_port":
                services.add(finding.get("service", "unknown"))

        # 3. Vector: Search for CVEs related to discovered services
        cve_context = []
        if self.vector_store and services:
            for service in list(services)[:5]:  # Limit to top 5 services
                try:
                    cves = self.vector_store.search_cves(
                        query=f"{service} vulnerability",
                        n_results=3
                    )
                    cve_context.extend(cves)
                except Exception as e:
                    self.logger.warning(f"Failed to search CVEs for {service}: {e}")

        context["relevant_cves"] = cve_context

        # 4. Vector: Exploitation techniques
        if self.vector_store:
            try:
                exploit_techniques = self.vector_store.search_mitre_techniques(
                    query="exploit vulnerability privilege escalation",
                    n_results=5
                )
                context["exploitation_techniques"] = exploit_techniques
            except Exception as e:
                self.logger.warning(f"Failed to search exploitation techniques: {e}")
                context["exploitation_techniques"] = []
        else:
            context["exploitation_techniques"] = []

        return context

    def build_context_for_planning(
        self,
        all_findings: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        """
        Build comprehensive context for strategic planning

        This is for the Planning Agent - needs full picture

        Args:
            all_findings: All findings from recon and analysis
            objectives: Operation objectives

        Returns:
            Comprehensive context for planning
        """
        context = {
            "phase": "planning",
            "objectives": objectives,
            "total_findings": len(all_findings)
        }

        # 1. Graph: Complete attack surface
        if self.world_model:
            try:
                attack_surface = self.world_model.get_graph_statistics()
                context["attack_surface"] = attack_surface
            except Exception as e:
                self.logger.warning(f"Failed to get graph statistics: {e}")
                context["attack_surface"] = {}
        else:
            context["attack_surface"] = {}

        # 2. Vector: Historical successful attack chains
        if self.vector_store:
            try:
                similar_operations = self.vector_store.search_operation_history(
                    query=f"Similar findings: {', '.join(objectives)}",
                    n_results=3
                )
                context["similar_past_operations"] = similar_operations
            except Exception as e:
                self.logger.warning(f"Failed to search operation history: {e}")
                context["similar_past_operations"] = []
        else:
            context["similar_past_operations"] = []

        # 3. Vector: MITRE ATT&CK attack chain templates
        if self.vector_store:
            try:
                attack_chain_templates = self.vector_store.search_mitre_techniques(
                    query="complete attack chain initial access persistence exfiltration",
                    n_results=10
                )
                context["attack_chain_templates"] = attack_chain_templates
            except Exception as e:
                self.logger.warning(f"Failed to search attack chains: {e}")
                context["attack_chain_templates"] = []
        else:
            context["attack_chain_templates"] = []

        # 4. Full operation history (for Planning Agent only)
        context["full_operation_history"] = self.operation_history

        return context

    def record_action(self, action: Dict[str, Any]):
        """
        Record an action to short-term memory

        Args:
            action: Action details (agent, action_type, target, etc.)
        """
        self.operation_history.append({
            "timestamp": datetime.now().isoformat(),
            **action
        })

        # Keep only last 50 actions in memory
        if len(self.operation_history) > 50:
            self.operation_history = self.operation_history[-50:]

    def get_context_summary(self) -> str:
        """
        Generate human-readable context summary for LLM

        Returns:
            Formatted context summary
        """
        # Vector store stats
        vector_stats = {}
        if self.vector_store:
            try:
                vector_stats = self.vector_store.get_stats()
            except Exception as e:
                self.logger.warning(f"Failed to get vector stats: {e}")

        # Graph stats
        graph_stats = {}
        if self.world_model:
            try:
                graph_stats = self.world_model.get_graph_statistics()
            except Exception as e:
                self.logger.warning(f"Failed to get graph stats: {e}")

        # Recent actions
        recent_cutoff = (datetime.now() - timedelta(minutes=10)).isoformat()
        recent_actions = [
            a for a in self.operation_history
            if a.get('timestamp', '') > recent_cutoff
        ]

        summary = f"""
# Current Knowledge Base Status

## Graph Database (Infrastructure State)
{json.dumps(graph_stats, indent=2)}

## Vector Database (Semantic Knowledge)
{json.dumps(vector_stats, indent=2)}

## Operation History
- Actions recorded: {len(self.operation_history)}
- Recent actions (last 10 min): {len(recent_actions)}
"""
        return summary

    def clear_history(self):
        """Clear operation history"""
        self.operation_history = []
        self.logger.info("Operation history cleared")

    def export_context(self, filepath: str):
        """
        Export current context to JSON file

        Args:
            filepath: Path to save context
        """
        context_data = {
            "timestamp": datetime.now().isoformat(),
            "operation_history": self.operation_history,
            "vector_stats": self.vector_store.get_stats() if self.vector_store else {},
            "graph_stats": self.world_model.get_graph_statistics() if self.world_model else {}
        }

        with open(filepath, 'w') as f:
            json.dump(context_data, f, indent=2)

        self.logger.info(f"Context exported to {filepath}")
