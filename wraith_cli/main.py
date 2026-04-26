"""
WRAITH CLI — main entry point.

Usage:
    wraith scan /path/to/project
    wraith scan /path/to/project --url https://target.com --type full
    wraith llm-redteam https://target.com/api/chat
    wraith osint example.com
    wraith rl-stats
    wraith report /path/to/report.json --format html
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wraith_cli import __version__
from wraith_cli.config import WraithConfig, LLMProvider

console = Console()

BANNER = r"""
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
  Weakness Reasoning & AI Threat Hunter
"""


@click.group()
@click.version_option(version=__version__, prog_name="wraith")
def cli() -> None:
    """WRAITH — Multi-agent AI-powered penetration testing framework."""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--url", "-u", default="", help="Target URL for web/API scanning")
@click.option("--type", "-t", "scan_type", default="full",
              type=click.Choice(["full", "code", "web", "api", "llm"]),
              help="Scan type")
@click.option("--output", "-o", default="wraith_output", help="Output directory")
@click.option("--provider", "-p", default="openai",
              type=click.Choice(["openai", "anthropic", "ollama"]),
              help="LLM provider")
@click.option("--model", "-m", default=None, help="LLM model name")
@click.option("--api-key", "-k", default=None, help="LLM API key (or set env var)")
@click.option("--ollama-url", default="http://localhost:11434", help="Ollama base URL")
def scan(
    target: str,
    url: str,
    scan_type: str,
    output: str,
    provider: str,
    model: str,
    api_key: str,
    ollama_url: str,
) -> None:
    """Run a vulnerability scan on a target directory or project."""
    console.print(Panel(BANNER, style="bold red", border_style="red"))
    console.print(f"  [dim]v{__version__} | {provider} | {scan_type} scan[/]\n")

    config = WraithConfig()
    config.llm.provider = LLMProvider(provider)
    if model:
        config.llm.model = model
    if api_key:
        config.llm.api_key = api_key
    if provider == "ollama":
        config.llm.base_url = ollama_url

    from wraith_cli.engine import ScanEngine
    engine = ScanEngine(config)
    asyncio.run(engine.run_scan(target, scan_type=scan_type, target_url=url, output_dir=output))


@cli.command("llm-redteam")
@click.argument("target_url")
@click.option("--provider", "-p", default="openai", help="LLM provider for analysis")
@click.option("--model", "-m", default=None, help="LLM model")
@click.option("--api-key", "-k", default=None, help="API key")
@click.option("--output", "-o", default="wraith_output", help="Output directory")
def llm_redteam(target_url: str, provider: str, model: str, api_key: str, output: str) -> None:
    """Red-team test an LLM-powered endpoint (OWASP LLM Top 10)."""
    console.print(Panel(BANNER, style="bold red", border_style="red"))
    console.print(f"  [bold]LLM Red Team[/] → {target_url}\n")

    config = WraithConfig()
    config.llm.provider = LLMProvider(provider)
    if model:
        config.llm.model = model
    if api_key:
        config.llm.api_key = api_key

    from wraith_cli.agents.base import MessageBus
    from wraith_cli.agents.llm_redteam import LLMRedTeamAgent

    agent = LLMRedTeamAgent(config, MessageBus())
    result = asyncio.run(agent.run({"target_url": target_url}, {}))

    if result.findings:
        console.print(f"\n[bold red]⚠️  {len(result.findings)} vulnerabilities found:[/]\n")
        for f in result.findings:
            console.print(f"  [{f.get('severity', 'medium').upper()}] {f.get('title', 'Unknown')}")
    else:
        console.print("\n[bold green]✅ No LLM vulnerabilities detected[/]\n")

    Path(output).mkdir(parents=True, exist_ok=True)
    Path(output, "llm_redteam.json").write_text(json.dumps(result.to_dict(), indent=2, default=str))
    console.print(f"  📁 Results: {output}/llm_redteam.json\n")


@cli.command()
@click.argument("domain")
@click.option("--provider", "-p", default="openai", help="LLM provider")
@click.option("--api-key", "-k", default=None, help="API key")
def osint(domain: str, provider: str, api_key: str) -> None:
    """Perform OSINT reconnaissance on a domain."""
    console.print(Panel(BANNER, style="bold red", border_style="red"))
    console.print(f"  [bold]OSINT Recon[/] → {domain}\n")

    config = WraithConfig()
    config.llm.provider = LLMProvider(provider)
    if api_key:
        config.llm.api_key = api_key

    from wraith_cli.agents.base import MessageBus
    from wraith_cli.agents.osint_recon import OSINTReconAgent

    agent = OSINTReconAgent(config, MessageBus())
    result = asyncio.run(agent.run({"target": domain}, {}))

    console.print(json.dumps(result.data, indent=2, default=str))


@cli.command("rl-stats")
def rl_stats() -> None:
    """Show reinforcement learning agent statistics."""
    from wraith_cli.rl.policy import RLPolicy
    from wraith_cli.config import RLConfig

    policy = RLPolicy(RLConfig())
    policy.load()

    stats = policy.get_stats()
    console.print(Panel(BANNER, style="bold red", border_style="red"))
    console.print("[bold]🎰 RL Agent Statistics[/]\n")

    table = Table(title="Bandit Arms (Top 10 by Q-value)")
    table.add_column("Vulnerability Class", style="cyan")
    table.add_column("Q-value", justify="right")
    table.add_column("Pulls", justify="right")
    table.add_column("Total Reward", justify="right")
    table.add_column("Best Reward", justify="right")

    for arm in stats.get("top_arms", []):
        table.add_row(
            arm["name"],
            f"{arm['q_value']:.3f}",
            str(arm["pulls"]),
            f"{arm['total_reward']:.1f}",
            f"{arm['best_reward']:.1f}",
        )

    console.print(table)
    console.print(f"\n  Strategy: {stats.get('strategy', 'N/A')}")
    console.print(f"  Episodes: {stats.get('episode_count', 0)}")
    console.print(f"  Replay buffer: {stats.get('replay_size', 0)} experiences")
    if stats.get("epsilon") is not None:
        console.print(f"  Epsilon: {stats['epsilon']:.4f}")
    console.print()


@cli.command()
@click.argument("report_path", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["json", "markdown", "html"]),
              help="Output format")
@click.option("--output", "-o", default=None, help="Output path")
def report(report_path: str, fmt: str, output: Optional[str]) -> None:
    """Convert a JSON report to another format."""
    data = json.loads(Path(report_path).read_text())
    gen = ReportGenerator(data)

    if output is None:
        output = f"wraith_report.{fmt}" if fmt != "markdown" else "wraith_report.md"

    out_path = Path(output)
    if fmt == "json":
        gen.to_json(out_path)
    elif fmt == "markdown":
        gen.to_markdown(out_path)
    else:
        gen.to_html(out_path)

    console.print(f"[green]✅ Report exported to {out_path}[/]")


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
