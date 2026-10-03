"""
Tests for LLM JSON Parsing

Verifies robust JSON extraction from LLM responses with various edge cases.
"""

import pytest
from unittest.mock import Mock, AsyncMock
from src.medusa.core.llm.client import LLMClient
from src.medusa.core.llm.config import LLMConfig
from src.medusa.core.llm.providers.base import BaseLLMProvider


class MockProvider(BaseLLMProvider):
    """Mock LLM provider for testing"""
    PROVIDER_NAME = "mock"

    async def generate(self, prompt, **kwargs):
        return Mock(content='{"test": "data"}', provider="mock", tokens_used=10, latency_ms=100, metadata={})

    async def health_check(self):
        return True

    async def get_model_info(self):
        return {"model": "mock", "version": "1.0"}


@pytest.fixture
def llm_client():
    """Create LLM client with mock provider"""
    config = LLMConfig(provider="mock")
    provider = MockProvider()
    return LLMClient(config=config, provider=provider)


class TestJSONExtraction:
    """Test JSON extraction from various response formats"""

    def test_pure_json_object(self, llm_client):
        """Test parsing pure JSON object"""
        response = '{"key": "value", "number": 42}'
        result = llm_client._extract_json_from_response(response)
        assert result == {"key": "value", "number": 42}

    def test_pure_json_array(self, llm_client):
        """Test parsing pure JSON array"""
        response = '[{"id": 1}, {"id": 2}]'
        result = llm_client._extract_json_from_response(response)
        assert result == [{"id": 1}, {"id": 2}]

    def test_json_in_markdown_code_block(self, llm_client):
        """Test extracting JSON from markdown code block"""
        response = '''```json
{
    "action": "scan",
    "target": "192.168.1.1"
}
```'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"action": "scan", "target": "192.168.1.1"}

    def test_json_in_plain_code_block(self, llm_client):
        """Test extracting JSON from plain code block without language tag"""
        response = '''```
{"status": "success", "data": [1, 2, 3]}
```'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"status": "success", "data": [1, 2, 3]}

    def test_json_with_surrounding_text(self, llm_client):
        """Test extracting JSON when surrounded by text"""
        response = '''Here is the analysis:
{
    "findings": ["port 80 open", "port 443 open"],
    "severity": "low"
}
This concludes the analysis.'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"findings": ["port 80 open", "port 443 open"], "severity": "low"}

    def test_json_with_trailing_comma_object(self, llm_client):
        """Test repair of trailing comma in object"""
        response = '''{
    "name": "test",
    "value": 123,
}'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"name": "test", "value": 123}

    def test_json_with_trailing_comma_array(self, llm_client):
        """Test repair of trailing comma in array"""
        response = '''[
    "item1",
    "item2",
]'''
        result = llm_client._extract_json_from_response(response)
        assert result == ["item1", "item2"]

    def test_json_with_comments(self, llm_client):
        """Test removal of comments from JSON"""
        response = '''{
    // This is a comment
    "key": "value",
    /* Multi-line
       comment */
    "number": 42
}'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"key": "value", "number": 42}

    def test_json_with_multiple_trailing_commas(self, llm_client):
        """Test repair of multiple trailing commas"""
        response = '''{
    "a": 1,
    "b": 2,,
    "c": 3,
}'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"a": 1, "b": 2, "c": 3}

    def test_nested_json(self, llm_client):
        """Test parsing nested JSON structures"""
        response = '''{
    "level1": {
        "level2": {
            "level3": ["a", "b", "c"]
        }
    }
}'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"level1": {"level2": {"level3": ["a", "b", "c"]}}}

    def test_json_with_special_characters(self, llm_client):
        """Test JSON with special characters in strings"""
        response = '''{
    "message": "Hello, world!",
    "path": "/usr/local/bin",
    "regex": "^[a-z]+$"
}'''
        result = llm_client._extract_json_from_response(response)
        assert result["message"] == "Hello, world!"
        assert result["path"] == "/usr/local/bin"
        assert result["regex"] == "^[a-z]+$"

    def test_complex_real_world_example(self, llm_client):
        """Test complex real-world LLM response"""
        response = '''Based on the reconnaissance findings, here is the recommended strategy:

```json
{
    "recommended_actions": [
        {
            "action": "port_scan",
            "ports": "1-1000",
            "technique_id": "T1046",
            "priority": "high"
        },
        {
            "action": "web_fingerprint",
            "technique_id": "T1595.002",
            "priority": "medium"
        }
    ],
    "risk_assessment": "LOW",
    "estimated_duration": "10 minutes"
}
```

This strategy focuses on non-intrusive reconnaissance.'''
        result = llm_client._extract_json_from_response(response)
        assert "recommended_actions" in result
        assert len(result["recommended_actions"]) == 2
        assert result["risk_assessment"] == "LOW"


class TestJSONExtractionEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_string(self, llm_client):
        """Test error on empty string"""
        with pytest.raises(ValueError, match="Invalid response type"):
            llm_client._extract_json_from_response("")

    def test_none_input(self, llm_client):
        """Test error on None input"""
        with pytest.raises(ValueError, match="Invalid response type"):
            llm_client._extract_json_from_response(None)

    def test_no_json_found(self, llm_client):
        """Test error when no JSON is found"""
        with pytest.raises(ValueError, match="No JSON object found"):
            llm_client._extract_json_from_response("This is just plain text")

    def test_invalid_json_structure(self, llm_client):
        """Test error on completely invalid JSON"""
        with pytest.raises(ValueError, match="Invalid JSON"):
            llm_client._extract_json_from_response("{this is not valid json at all")

    def test_json_parses_to_string(self, llm_client):
        """Test error when JSON parses to string instead of dict/list"""
        # This shouldn't happen, but test the validation
        response = '"just a string"'
        with pytest.raises(ValueError, match="not dict/list"):
            llm_client._extract_json_from_response(response)

    def test_json_parses_to_number(self, llm_client):
        """Test error when JSON parses to number instead of dict/list"""
        response = '42'
        with pytest.raises(ValueError, match="not dict/list"):
            llm_client._extract_json_from_response(response)

    def test_malformed_beyond_repair(self, llm_client):
        """Test JSON that cannot be repaired"""
        response = '''{
    "key": "value with unmatched quote
    "another": "value"
}'''
        with pytest.raises(ValueError, match="Invalid JSON"):
            llm_client._extract_json_from_response(response)


class TestHelperMethods:
    """Test helper methods for JSON extraction"""

    def test_strip_markdown_code_blocks(self, llm_client):
        """Test markdown code block stripping"""
        text = "```json\n{\"key\": \"value\"}\n```"
        result = llm_client._strip_markdown_code_blocks(text)
        assert result == '{"key": "value"}'

    def test_strip_plain_code_blocks(self, llm_client):
        """Test plain code block stripping"""
        text = "```\n{\"key\": \"value\"}\n```"
        result = llm_client._strip_markdown_code_blocks(text)
        assert result == '{"key": "value"}'

    def test_strip_multiple_code_blocks(self, llm_client):
        """Test stripping multiple code blocks"""
        text = "```json\nblock1\n```\ntext\n```\nblock2\n```"
        result = llm_client._strip_markdown_code_blocks(text)
        assert "```" not in result

    def test_extract_json_boundaries_object(self, llm_client):
        """Test extracting object boundaries"""
        text = 'Some text {"key": "value"} more text'
        result = llm_client._extract_json_boundaries(text)
        assert result == '{"key": "value"}'

    def test_extract_json_boundaries_array(self, llm_client):
        """Test extracting array boundaries"""
        text = 'Some text ["a", "b", "c"] more text'
        result = llm_client._extract_json_boundaries(text)
        assert result == '["a", "b", "c"]'

    def test_extract_json_boundaries_nested(self, llm_client):
        """Test extracting nested JSON"""
        text = 'Text {"outer": {"inner": "value"}} text'
        result = llm_client._extract_json_boundaries(text)
        assert result == '{"outer": {"inner": "value"}}'

    def test_extract_json_boundaries_none_found(self, llm_client):
        """Test when no JSON boundaries found"""
        text = "No JSON here"
        result = llm_client._extract_json_boundaries(text)
        assert result is None

    def test_repair_json_trailing_commas(self, llm_client):
        """Test repairing trailing commas"""
        json_str = '{"a": 1, "b": 2,}'
        result = llm_client._repair_json_text(json_str)
        assert result == '{"a": 1, "b": 2}'

    def test_repair_json_comments(self, llm_client):
        """Test removing comments"""
        json_str = '''{
    "key": "value" // comment
}'''
        result = llm_client._repair_json_text(json_str)
        assert "//" not in result

    def test_repair_json_multiple_commas(self, llm_client):
        """Test repairing multiple consecutive commas"""
        json_str = '{"a": 1,, "b": 2}'
        result = llm_client._repair_json_text(json_str)
        assert ",," not in result


class TestIntegrationWithRealResponses:
    """Test with realistic LLM response patterns"""

    def test_chatgpt_style_response(self, llm_client):
        """Test typical ChatGPT-style response"""
        response = '''I'll analyze the target for you.

```json
{
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "severity": "high",
            "cve": "CVE-2021-1234"
        }
    ],
    "recommendations": [
        "Update database library",
        "Implement input validation"
    ]
}
```

Let me know if you need more details!'''
        result = llm_client._extract_json_from_response(response)
        assert "vulnerabilities" in result
        assert "recommendations" in result

    def test_claude_style_response(self, llm_client):
        """Test typical Claude-style response"""
        response = '''Here's my analysis:

{
    "phase": "reconnaissance",
    "actions": [
        {
            "tool": "nmap",
            "args": "-sV -p-",
            "priority": 1
        },
        {
            "tool": "amass",
            "args": "enum -d example.com",
            "priority": 2
        }
    ],
    "notes": "Start with network mapping"
}'''
        result = llm_client._extract_json_from_response(response)
        assert result["phase"] == "reconnaissance"
        assert len(result["actions"]) == 2

    def test_response_with_explanation_after_json(self, llm_client):
        """Test response with explanation after JSON"""
        response = '''{
    "result": "success",
    "data": [1, 2, 3]
}

The above JSON contains the scan results. The data array shows three open ports.'''
        result = llm_client._extract_json_from_response(response)
        assert result == {"result": "success", "data": [1, 2, 3]}

    def test_response_with_markdown_formatting(self, llm_client):
        """Test response with markdown formatting around JSON"""
        response = '''## Analysis Results

Here are the findings:

```json
{
    "findings": ["Finding 1", "Finding 2"],
    "status": "complete"
}
```

### Next Steps
Continue with exploitation phase.'''
        result = llm_client._extract_json_from_response(response)
        assert result["status"] == "complete"
        assert len(result["findings"]) == 2
