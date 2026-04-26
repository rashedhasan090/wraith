#!/usr/bin/env python3
"""Example: Scan a local project with WRAITH."""

import asyncio
from wraith_cli.config import WraithConfig, LLMProvider
from wraith_cli.engine import ScanEngine


async def main():
    config = WraithConfig()
    config.llm.provider = LLMProvider.OPENAI  # or ANTHROPIC, OLLAMA
    # config.llm.api_key = "sk-..."  # Or set OPENAI_API_KEY env var

    engine = ScanEngine(config)
    results = await engine.run_scan(
        target="./path/to/your/project",
        scan_type="full",
        output_dir="wraith_output",
    )
    print(f"Found {len(results['findings'])} vulnerabilities")


if __name__ == "__main__":
    asyncio.run(main())
