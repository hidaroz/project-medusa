"""
Unit tests for VectorStore
Tests ChromaDB integration and search functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


@pytest.fixture
def mock_chroma_client():
    """Mock ChromaDB client"""
    mock = MagicMock()
    mock_collection = MagicMock()
    mock_collection.count.return_value = 100
    mock_collection.query.return_value = {
        "ids": [["doc1", "doc2"]],
        "documents": [["Document 1", "Document 2"]],
        "metadatas": [[{"key": "value1"}, {"key": "value2"}]],
        "distances": [[0.1, 0.2]]
    }
    mock.get_or_create_collection.return_value = mock_collection
    return mock


def test_vector_store_initialization(mock_chroma_client):
    """Test VectorStore initializes with ChromaDB"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()
        assert store.client is not None
        assert "mitre_attack" in store.collections
        assert "cve_database" in store.collections
        assert "tool_docs" in store.collections
        assert "operation_history" in store.collections


def test_vector_store_has_required_collections(mock_chroma_client):
    """Test VectorStore creates all required collections"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Should have exactly 4 collections
        assert len(store.collections) == 4

        # Verify collection names
        expected_collections = [
            "mitre_attack",
            "cve_database",
            "tool_docs",
            "operation_history"
        ]
        for collection_name in expected_collections:
            assert collection_name in store.collections


def test_vector_store_search_mitre(mock_chroma_client):
    """Test MITRE ATT&CK search"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock search results
        store.collections["mitre_attack"].query.return_value = {
            "ids": [["T1046"]],
            "documents": [["Network Service Scanning"]],
            "metadatas": [[{
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": "discovery"
            }]],
            "distances": [[0.1]]
        }

        results = store.search_mitre_techniques("port scanning", top_k=5)

        assert len(results) > 0
        assert results[0]["technique_id"] == "T1046"
        assert "Network Service Scanning" in results[0]["technique_name"]


def test_vector_store_search_cves(mock_chroma_client):
    """Test CVE database search"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock CVE search results
        store.collections["cve_database"].query.return_value = {
            "ids": [["CVE-2021-44228"]],
            "documents": [["Apache Log4j2 RCE"]],
            "metadatas": [[{
                "cve_id": "CVE-2021-44228",
                "severity": "critical",
                "cvss": 10.0
            }]],
            "distances": [[0.05]]
        }

        results = store.search_cves("java remote code execution", top_k=3)

        assert len(results) > 0
        assert results[0]["cve_id"] == "CVE-2021-44228"
        assert results[0]["severity"] == "critical"


def test_vector_store_search_tool_docs(mock_chroma_client):
    """Test tool documentation search"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock tool docs search
        store.collections["tool_docs"].query.return_value = {
            "ids": [["nmap-1"]],
            "documents": [["nmap -sV -p- <target>"]],
            "metadatas": [[{
                "tool": "nmap",
                "command": "nmap -sV -p-",
                "category": "reconnaissance"
            }]],
            "distances": [[0.2]]
        }

        results = store.search_tool_usage("scan all ports", top_k=3)

        assert len(results) > 0
        assert results[0]["tool"] == "nmap"


def test_vector_store_get_stats(mock_chroma_client):
    """Test getting vector store statistics"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        stats = store.get_stats()

        assert "mitre_attack" in stats
        assert "cve_database" in stats
        assert "tool_docs" in stats
        assert "operation_history" in stats

        # Each collection should have a count
        assert stats["mitre_attack"]["count"] == 100
        assert stats["cve_database"]["count"] == 100


def test_vector_store_top_k_parameter(mock_chroma_client):
    """Test top_k parameter limits results"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock multiple results
        store.collections["mitre_attack"].query.return_value = {
            "ids": [["T1", "T2", "T3", "T4", "T5"]],
            "documents": [["Doc1", "Doc2", "Doc3", "Doc4", "Doc5"]],
            "metadatas": [[
                {"technique_id": f"T{i}"} for i in range(1, 6)
            ]],
            "distances": [[0.1, 0.2, 0.3, 0.4, 0.5]]
        }

        # Request only top 3
        results = store.search_mitre_techniques("test", top_k=3)

        # Should call query with n_results=3
        store.collections["mitre_attack"].query.assert_called_once()
        call_args = store.collections["mitre_attack"].query.call_args
        assert call_args[1]["n_results"] == 3


def test_vector_store_embedding_provider(mock_chroma_client):
    """Test VectorStore can use different embedding providers"""
    from medusa.context.vector_store import VectorStore

    # Test with local embeddings
    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore(embedding_provider="local")
        assert store.embedding_provider == "local"

    # Test with Bedrock embeddings
    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore(embedding_provider="bedrock")
        assert store.embedding_provider == "bedrock"


def test_vector_store_persist_directory(mock_chroma_client):
    """Test VectorStore uses correct persist directory"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client) as mock_client:
        store = VectorStore(persist_directory="/custom/path")

        # Should have called PersistentClient with custom path
        mock_client.assert_called_once()


def test_vector_store_add_to_operation_history(mock_chroma_client):
    """Test adding operation to history"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Add operation to history
        operation_data = {
            "operation_id": "TEST-001",
            "target": "test.example.com",
            "findings": ["Finding 1", "Finding 2"]
        }

        store.add_operation_to_history(
            operation_id="TEST-001",
            summary="Test operation summary",
            metadata=operation_data
        )

        # Should have called add on operation_history collection
        store.collections["operation_history"].add.assert_called_once()


def test_vector_store_search_operation_history(mock_chroma_client):
    """Test searching operation history"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock history search
        store.collections["operation_history"].query.return_value = {
            "ids": [["OP-001"]],
            "documents": [["Previous SQL injection assessment"]],
            "metadatas": [[{
                "operation_id": "OP-001",
                "target": "oldtarget.com"
            }]],
            "distances": [[0.15]]
        }

        results = store.search_operation_history("SQL injection", top_k=5)

        assert len(results) > 0
        assert results[0]["operation_id"] == "OP-001"


def test_vector_store_handles_empty_results(mock_chroma_client):
    """Test VectorStore handles empty search results gracefully"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock empty results
        store.collections["mitre_attack"].query.return_value = {
            "ids": [[]],
            "documents": [[]],
            "metadatas": [[]],
            "distances": [[]]
        }

        results = store.search_mitre_techniques("nonexistent", top_k=5)

        # Should return empty list, not error
        assert results == []


def test_vector_store_collection_count(mock_chroma_client):
    """Test getting collection counts"""
    from medusa.context.vector_store import VectorStore

    with patch('chromadb.PersistentClient', return_value=mock_chroma_client):
        store = VectorStore()

        # Mock different counts for each collection
        store.collections["mitre_attack"].count.return_value = 600
        store.collections["cve_database"].count.return_value = 150
        store.collections["tool_docs"].count.return_value = 200
        store.collections["operation_history"].count.return_value = 10

        stats = store.get_stats()

        assert stats["mitre_attack"]["count"] == 600
        assert stats["cve_database"]["count"] == 150
        assert stats["tool_docs"]["count"] == 200
        assert stats["operation_history"]["count"] == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])