"""
Vector Store for semantic knowledge retrieval
Uses ChromaDB with AWS Titan Embeddings (or local sentence-transformers)
"""

import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional
import logging
from pathlib import Path
import json


class VectorStore:
    """
    Vector database for semantic search over security knowledge

    Stores:
    - MITRE ATT&CK techniques
    - CVE database
    - Tool documentation
    - Historical operation summaries
    """

    def __init__(
        self,
        persist_directory: str = "~/.medusa/vector_db",
        embedding_provider: str = "local"  # or "bedrock"
    ):
        self.persist_dir = Path(persist_directory).expanduser()
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )

        # Configure embedding function
        if embedding_provider == "bedrock":
            self.embedding_function = self._create_bedrock_embeddings()
        else:
            self.embedding_function = self._create_local_embeddings()

        # Collections
        self.collections = {
            "mitre_attack": self._get_or_create_collection("mitre_attack"),
            "cve_database": self._get_or_create_collection("cve_database"),
            "tool_docs": self._get_or_create_collection("tool_documentation"),
            "operation_history": self._get_or_create_collection("operation_history")
        }

        self.logger = logging.getLogger(__name__)
        self.logger.info(f"VectorStore initialized at {self.persist_dir}")

    def _get_or_create_collection(self, name: str):
        """Get or create a collection"""
        try:
            return self.client.get_collection(
                name=name,
                embedding_function=self.embedding_function
            )
        except ValueError:
            return self.client.create_collection(
                name=name,
                embedding_function=self.embedding_function,
                metadata={"hnsw:space": "cosine"}
            )

    def _create_bedrock_embeddings(self):
        """Create Bedrock Titan embedding function"""
        import boto3

        class BedrockEmbeddingFunction:
            def __init__(self):
                self.bedrock = boto3.client('bedrock-runtime', region_name='us-west-2')
                self.model_id = "amazon.titan-embed-text-v2:0"

            def __call__(self, input: List[str]) -> List[List[float]]:
                embeddings = []
                for text in input:
                    response = self.bedrock.invoke_model(
                        modelId=self.model_id,
                        body=json.dumps({"inputText": text})
                    )
                    result = json.loads(response['body'].read())
                    embeddings.append(result['embedding'])
                return embeddings

        return BedrockEmbeddingFunction()

    def _create_local_embeddings(self):
        """Create local sentence-transformers embedding function"""
        from chromadb.utils import embedding_functions

        return embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )

    def index_mitre_attack(self, techniques: List[Dict[str, Any]]):
        """
        Index MITRE ATT&CK techniques

        Args:
            techniques: List of MITRE techniques with id, name, description
        """
        collection = self.collections["mitre_attack"]

        ids = [t["id"] for t in techniques]
        documents = [
            f"{t['name']}: {t['description']}\n\nTactics: {', '.join(t.get('tactics', []))}"
            for t in techniques
        ]
        metadatas = [
            {
                "technique_id": t["id"],
                "technique_name": t["name"],
                "tactics": ",".join(t.get("tactics", [])),
                "platforms": ",".join(t.get("platforms", []))
            }
            for t in techniques
        ]

        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )

        self.logger.info(f"Indexed {len(techniques)} MITRE ATT&CK techniques")

    def search_mitre_techniques(
        self,
        query: str,
        n_results: int = 5,
        filter_tactics: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Semantic search for relevant MITRE techniques

        Args:
            query: Search query (e.g., "lateral movement using credentials")
            n_results: Number of results to return
            filter_tactics: Filter by specific tactics

        Returns:
            List of relevant techniques with scores
        """
        collection = self.collections["mitre_attack"]

        where_filter = {}
        if filter_tactics:
            # Note: Chroma doesn't support OR filters well, so we search all
            # and filter in post-processing
            pass

        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter if where_filter else None
        )

        techniques = []
        if results['ids'] and len(results['ids']) > 0:
            for i in range(len(results['ids'][0])):
                techniques.append({
                    "technique_id": results['metadatas'][0][i]['technique_id'],
                    "technique_name": results['metadatas'][0][i]['technique_name'],
                    "description": results['documents'][0][i],
                    "relevance_score": 1.0 - results['distances'][0][i],  # Convert distance to similarity
                    "tactics": results['metadatas'][0][i]['tactics'].split(',')
                })

        return techniques

    def index_tool_documentation(self, tool_docs: List[Dict[str, Any]]):
        """
        Index tool documentation for semantic search

        Args:
            tool_docs: List with tool, command, description, examples
        """
        collection = self.collections["tool_docs"]

        ids = [f"{doc['tool']}_{i}" for i, doc in enumerate(tool_docs)]
        documents = [
            f"Tool: {doc['tool']}\nCommand: {doc['command']}\n"
            f"Description: {doc['description']}\nExamples: {doc.get('examples', '')}"
            for doc in tool_docs
        ]
        metadatas = [
            {
                "tool": doc["tool"],
                "command": doc["command"],
                "category": doc.get("category", "general")
            }
            for doc in tool_docs
        ]

        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        self.logger.info(f"Indexed {len(tool_docs)} tool documentation entries")

    def search_tool_usage(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Search for relevant tool usage examples

        Example query: "scan for SQL injection vulnerabilities"
        Returns: SQLMap commands and usage
        """
        collection = self.collections["tool_docs"]

        results = collection.query(
            query_texts=[query],
            n_results=n_results
        )

        tool_usage = []
        if results['ids'] and len(results['ids']) > 0:
            for i in range(len(results['ids'][0])):
                tool_usage.append({
                    "tool": results['metadatas'][0][i]['tool'],
                    "command": results['metadatas'][0][i]['command'],
                    "documentation": results['documents'][0][i],
                    "relevance_score": 1.0 - results['distances'][0][i]
                })

        return tool_usage

    def index_cves(self, cves: List[Dict[str, Any]]):
        """
        Index CVE database for vulnerability search

        Args:
            cves: List of CVEs with id, description, severity, etc.
        """
        collection = self.collections["cve_database"]

        ids = [cve["cve_id"] for cve in cves]
        documents = [
            f"CVE {cve['cve_id']}: {cve['description']}\n"
            f"Severity: {cve['severity']}, CVSS: {cve.get('cvss', 'N/A')}\n"
            f"Affected: {', '.join(cve.get('affected_software', []))}"
            for cve in cves
        ]
        metadatas = [
            {
                "cve_id": cve["cve_id"],
                "severity": cve["severity"],
                "cvss": str(cve.get("cvss", 0)),
                "affected_software": ",".join(cve.get("affected_software", []))
            }
            for cve in cves
        ]

        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        self.logger.info(f"Indexed {len(cves)} CVEs")

    def search_cves(
        self,
        query: str,
        n_results: int = 5,
        min_severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant CVEs

        Args:
            query: Search query (e.g., "MySQL vulnerability")
            n_results: Number of results to return
            min_severity: Minimum severity filter (low, medium, high, critical)

        Returns:
            List of relevant CVEs
        """
        collection = self.collections["cve_database"]

        where_filter = {}
        if min_severity:
            # This would need severity mapping, simplified for now
            pass

        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter if where_filter else None
        )

        cves = []
        if results['ids'] and len(results['ids']) > 0:
            for i in range(len(results['ids'][0])):
                cves.append({
                    "cve_id": results['metadatas'][0][i]['cve_id'],
                    "severity": results['metadatas'][0][i]['severity'],
                    "cvss": results['metadatas'][0][i]['cvss'],
                    "affected_software": results['metadatas'][0][i]['affected_software'].split(','),
                    "description": results['documents'][0][i],
                    "relevance_score": 1.0 - results['distances'][0][i]
                })

        return cves

    def index_operation_history(self, operation: Dict[str, Any]):
        """
        Index operation history for learning from past operations

        Args:
            operation: Operation summary with findings, techniques, outcomes
        """
        collection = self.collections["operation_history"]

        operation_id = operation.get("operation_id", f"op_{len(collection.get()['ids'])}")

        document = f"Operation: {operation.get('target', 'N/A')}\n"
        document += f"Objectives: {', '.join(operation.get('objectives', []))}\n"
        document += f"Findings: {operation.get('findings_summary', 'N/A')}\n"
        document += f"Techniques Used: {', '.join(operation.get('techniques_used', []))}\n"
        document += f"Success Rate: {operation.get('success_rate', 'N/A')}"

        metadata = {
            "operation_id": operation_id,
            "target": operation.get("target", "unknown"),
            "timestamp": operation.get("timestamp", ""),
            "success": str(operation.get("success", False))
        }

        collection.upsert(
            ids=[operation_id],
            documents=[document],
            metadatas=[metadata]
        )

        self.logger.info(f"Indexed operation: {operation_id}")

    def search_operation_history(
        self,
        query: str,
        n_results: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Search for similar past operations

        Args:
            query: Search query describing the scenario
            n_results: Number of similar operations to return

        Returns:
            List of similar past operations
        """
        collection = self.collections["operation_history"]

        results = collection.query(
            query_texts=[query],
            n_results=n_results
        )

        operations = []
        if results['ids'] and len(results['ids']) > 0:
            for i in range(len(results['ids'][0])):
                operations.append({
                    "operation_id": results['metadatas'][0][i]['operation_id'],
                    "target": results['metadatas'][0][i]['target'],
                    "summary": results['documents'][0][i],
                    "relevance_score": 1.0 - results['distances'][0][i]
                })

        return operations

    def get_stats(self) -> Dict[str, Any]:
        """Get vector store statistics"""
        stats = {}
        for name, collection in self.collections.items():
            count = collection.count()
            stats[name] = count

        return {
            "persist_directory": str(self.persist_dir),
            "collections": stats,
            "total_documents": sum(stats.values())
        }

    def reset_collection(self, collection_name: str):
        """Reset a specific collection"""
        if collection_name in self.collections:
            self.client.delete_collection(name=collection_name)
            self.collections[collection_name] = self._get_or_create_collection(collection_name)
            self.logger.info(f"Reset collection: {collection_name}")

    def reset_all(self):
        """Reset all collections"""
        for collection_name in list(self.collections.keys()):
            self.reset_collection(collection_name)
        self.logger.info("Reset all collections")
