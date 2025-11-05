#!/usr/bin/env python3
"""
Quick test script to verify LLM response parsing fix
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from medusa.core.llm import LLMClient, LLMConfig

async def test_llm():
    """Test LLM with a simple prompt"""

    # Load config
    import yaml
    config_path = Path.home() / ".medusa" / "config.yaml"
    
    if not config_path.exists():
        print("❌ FAILED: Config file not found at ~/.medusa/config.yaml")
        print("   Please run 'medusa setup' first")
        return False
        
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Create LLM client
    llm_config = LLMConfig(
        api_key=config['api_key'],
        model=config['llm']['model'],
        temperature=config['llm']['temperature'],
        max_tokens=config['llm']['max_tokens'],
        timeout=config['llm']['timeout'],
        max_retries=config['llm']['max_retries']
    )

    client = LLMClient(llm_config)

    # Test with simple prompt
    print("Testing LLM response parsing...")
    try:
        response = await client._generate_with_retry(
            "Say 'Hello, MEDUSA is working!' in one sentence."
        )
        print(f"✅ SUCCESS: Got response: {response[:100]}...")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_llm())
    sys.exit(0 if success else 1)

