"""
Vector Store for Context Fusion Engine

Provides vector-based semantic search for MITRE ATT&CK techniques, CVE data,
tool documentation, and operation history.
"""

import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib


class VectorStore:
    """
    Vector database interface for semantic search and retrieval.

    Uses ChromaDB for vector storage and retrieval. Supports:
    - MITRE ATT&CK techniques
    - CVE vulnerability data
    - Tool documentation
    - Operation history
    """

    def __init__(self, persist_directory: Optional[str] = None):
        """
        Initialize vector store.

        Args:
            persist_directory: Directory for persistent storage.
                             Defaults to ~/.medusa/vector_store/
        """
        self.persist_directory = persist_directory or os.path.expanduser(
            "~/.medusa/vector_store"
        )
        os.makedirs(self.persist_directory, exist_ok=True)

        # For now, use in-memory storage until ChromaDB is installed
        # TODO: Replace with actual ChromaDB client
        self.collections = {
            "mitre": [],
            "cve": [],
            "tools": [],
            "operations": []
        }
        self._load_from_disk()

    def _load_from_disk(self):
        """Load vector store data from disk if it exists."""
        data_file = os.path.join(self.persist_directory, "vector_data.json")
        if os.path.exists(data_file):
            try:
                with open(data_file, 'r') as f:
                    self.collections = json.load(f)
            except Exception:
                pass

    def _save_to_disk(self):
        """Save vector store data to disk."""
        data_file = os.path.join(self.persist_directory, "vector_data.json")
        with open(data_file, 'w') as f:
            json.dump(self.collections, f, indent=2)

    def add_documents(
        self,
        collection_name: str,
        documents: List[Dict[str, Any]],
        embeddings: Optional[List[List[float]]] = None
    ):
        """
        Add documents to a collection.

        Args:
            collection_name: Name of the collection (mitre, cve, tools, operations)
            documents: List of documents with content and metadata
            embeddings: Optional pre-computed embeddings
        """
        if collection_name not in self.collections:
            self.collections[collection_name] = []

        for doc in documents:
            # Add unique ID if not present
            if 'id' not in doc:
                content_hash = hashlib.md5(
                    str(doc.get('content', '')).encode()
                ).hexdigest()
                doc['id'] = f"{collection_name}_{content_hash}"

            # Add timestamp
            if 'timestamp' not in doc:
                doc['timestamp'] = datetime.now().isoformat()

            # Check if document already exists
            existing_ids = {d.get('id') for d in self.collections[collection_name]}
            if doc['id'] not in existing_ids:
                self.collections[collection_name].append(doc)

        self._save_to_disk()

    def search(
        self,
        collection_name: str,
        query: str,
        n_results: int = 5,
        filter_dict: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for documents in a collection.

        Args:
            collection_name: Collection to search
            query: Search query
            n_results: Number of results to return
            filter_dict: Optional filters to apply

        Returns:
            List of matching documents with relevance scores
        """
        if collection_name not in self.collections:
            return []

        results = []
        query_lower = query.lower()
        query_terms = set(query_lower.split())

        for doc in self.collections[collection_name]:
            # Apply filters if provided
            if filter_dict:
                matches_filter = all(
                    doc.get(key) == value
                    for key, value in filter_dict.items()
                )
                if not matches_filter:
                    continue

            # Simple keyword-based relevance score
            # TODO: Replace with actual embedding similarity
            content = str(doc.get('content', '')).lower()
            doc_terms = set(content.split())

            # Calculate relevance score
            common_terms = query_terms & doc_terms
            if common_terms:
                relevance_score = len(common_terms) / len(query_terms)
                results.append({
                    **doc,
                    'relevance_score': relevance_score
                })

        # Sort by relevance score and return top N
        results.sort(key=lambda x: x['relevance_score'], reverse=True)
        return results[:n_results]

    def search_mitre_techniques(
        self,
        query: str,
        tactic: Optional[str] = None,
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """Search for MITRE ATT&CK techniques."""
        filter_dict = {'tactic': tactic} if tactic else None
        return self.search("mitre", query, n_results, filter_dict)

    def search_cve(
        self,
        query: str,
        severity: Optional[str] = None,
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """Search for CVE vulnerability data."""
        filter_dict = {'severity': severity} if severity else None
        return self.search("cve", query, n_results, filter_dict)

    def search_tools(
        self,
        query: str,
        tool_type: Optional[str] = None,
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """Search for tool documentation."""
        filter_dict = {'tool_type': tool_type} if tool_type else None
        return self.search("tools", query, n_results, filter_dict)

    def search_operation_history(
        self,
        query: str,
        success_only: bool = False,
        n_results: int = 3
    ) -> List[Dict[str, Any]]:
        """Search for similar past operations."""
        filter_dict = {'success': True} if success_only else None
        return self.search("operations", query, n_results, filter_dict)

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the vector store."""
        return {
            collection: len(docs)
            for collection, docs in self.collections.items()
        }
