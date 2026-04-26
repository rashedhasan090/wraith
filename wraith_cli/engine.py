"""
Core scan orchestration engine.

Coordinates all agents through the five-phase scan pipeline:
1. Reconnaissance → 2. Static Analysis → 3. Vulnerability Hunting →
4. Chain Synthesis → 5. Reporting

The RL bandit guides vulnerability class exploration across phases.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from wraith_cli.config import WraithConfig
from wraith_cli.agents.base import MessageBus, AgentResult
from wraith_cli.agents.recon import ReconAgent
from wraith_cli.agents.code_analyst import CodeAnalystAgent
from wraith_cli.agents.vuln_hunter import VulnHunterAgent
from wraith_cli.agents.cve_intel import CVEIntelAgent
from wraith_cli.agents.attack_chain import AttackChainAgent
from wraith_cli.agents.remediation import RemediationAgent
from wraith_cli.agents.poc_generator import PoCGeneratorAgent
from wraith_cli.agents.llm_redteam import LLMRedTeamAgent
from wraith_cli.agents.api_security import APISecurityAgent
from wraith_cli.agents.zero_day import ZeroDayAgent
from wraith_cli.agents.osint_recon import OSINTReconAgent
from wraith_cli.rl.policy import RLPolicy
from wraith_cli.rl.memory import Experience
from wraith_cli.reporting.report import ReportGenerator

console = Console()


class ScanEngine:
    """Orchestrates the full multi-agent scan pipeline."""

    def __init__(self, config: WraithConfig) -> None:
        self.config = config
        self.bus = MessageBus()
        self.rl_policy = RLPolicy(config.rl)
        self.results: dict[str, AgentResult] = {}
        self.all_findings: list[dict[str, Any]] = []

        # Try to load existing RL policy for cross-session learning
        self.rl_policy.load()

    async def run_scan(
        self,
        target: str,
        scan_type: str = "full",
        target_url: str = "",
        output_dir: str = "wraith_output",
    ) -> dict[str, Any]:
        """Execute a complete scan pipeline."""
        start_time = time.time()
        scan_config = {"target": target, "target_url": target_url, "scan_type": scan_type}

        console.print(f"\n[bold red]⚡ WRAITH[/] — Starting {scan_type} scan on [cyan]{target}[/]\n")

        # Phase 1: Reconnaissance
        with Progress(SpinnerColumn(), TextColumn("[bold]{task.description}"), console=console) as progress:
            task_id = progress.add_task("Phase 1: Reconnaissance...", total=None)
            recon_agent = ReconAgent(self.config, self.bus)
            recon_result = await recon_agent.run({"scan_config": scan_config}, {})
            self.results["recon"] = recon_result
            recon_data = recon_result.data
            progress.update(task_id, description=f"Phase 1: Recon complete — {recon_data.get('files_count', 0)} files mapped")

        # RL: Select vulnerability classes to explore
        rl_targets = self.rl_policy.select_actions(k=6)
        console.print(f"  [yellow]🎰 RL targeting:[/] {', '.join(rl_targets[:6])}\n")

        context = {"recon_data": recon_data}

        # Phase 2: Static Analysis (parallel agents)
        console.print("[bold]⏳ Phase 2: Static Analysis...[/]")

        code_task = {"scan_config": scan_config}
        cve_task = {}

        code_agent = CodeAnalystAgent(self.config, self.bus)
        cve_agent = CVEIntelAgent(self.config, self.bus)

        console.print("  [dim]├─ Code pattern scan + LLM semantic analysis[/]")
        console.print("  [dim]└─ CVE/NVD database correlation (parallel)[/]")

        code_result, cve_result = await asyncio.gather(
            code_agent.run(code_task, context),
            cve_agent.run(cve_task, context),
        )
        self.results["code_analyst"] = code_result
        self.results["cve_intel"] = cve_result
        self.all_findings.extend(code_result.findings)
        self.all_findings.extend(cve_result.findings)

        console.print(
            f"  [green]✓ Phase 2:[/] {len(code_result.findings)} code + "
            f"{len(cve_result.findings)} CVE findings\n"
        )

        # Phase 3: Vulnerability Hunting (RL-guided)
        with Progress(SpinnerColumn(), TextColumn("[bold]{task.description}"), console=console) as progress:
            task_id = progress.add_task("Phase 3: Vulnerability Hunting...", total=None)

            context["code_analyst_findings"] = code_result.findings
            vuln_agent = VulnHunterAgent(self.config, self.bus)
            vuln_result = await vuln_agent.run(
                {"scan_config": scan_config, "rl_targets": rl_targets},
                context,
            )
            self.results["vuln_hunter"] = vuln_result
            self.all_findings.extend(vuln_result.findings)

            # Parallel: Zero-day hypotheses + optional web scans
            tasks = []
            zero_day_agent = ZeroDayAgent(self.config, self.bus)
            tasks.append(zero_day_agent.run(
                {"existing_findings": self.all_findings},
                context,
            ))

            if target_url:
                llm_rt_agent = LLMRedTeamAgent(self.config, self.bus)
                api_agent = APISecurityAgent(self.config, self.bus)
                tasks.append(llm_rt_agent.run({"target_url": target_url}, context))
                tasks.append(api_agent.run({"target_url": target_url}, context))

            extra_results = await asyncio.gather(*tasks)
            for r in extra_results:
                self.results[r.agent_name] = r
                self.all_findings.extend(r.findings)

            progress.update(
                task_id,
                description=f"Phase 3: Hunting — {len(vuln_result.findings)} vulns + {len(extra_results)} specialist scans",
            )

        # Phase 4: Chain Synthesis + Remediation
        with Progress(SpinnerColumn(), TextColumn("[bold]{task.description}"), console=console) as progress:
            task_id = progress.add_task("Phase 4: Chain synthesis & remediation...", total=None)

            chain_agent = AttackChainAgent(self.config, self.bus)
            remed_agent = RemediationAgent(self.config, self.bus)

            chain_result, remed_result = await asyncio.gather(
                chain_agent.run({"vulnerabilities": self.all_findings}, context),
                remed_agent.run({"findings": self.all_findings}, context),
            )
            self.results["attack_chain"] = chain_result
            self.results["remediation"] = remed_result

            progress.update(
                task_id,
                description=f"Phase 4: {len(chain_result.findings)} chains, {len(remed_result.findings)} remediations",
            )

        # RL: Update policy from findings
        action_rewards = self.rl_policy.update_from_findings(self.all_findings, rl_targets)
        for finding in self.all_findings:
            state = {"target": target, "technologies": recon_data.get("technologies", [])}
            self.rl_policy.replay.add(Experience(
                state=state,
                action=finding.get("vuln_class", "unknown"),
                reward=action_rewards.get(finding.get("vuln_class", ""), 0.0),
                next_state=state,
                metadata={"finding_title": finding.get("title", "")},
            ))

        # Save RL policy for future sessions
        self.rl_policy.save()

        # Phase 5: Reporting
        elapsed = time.time() - start_time
        scan_data = {
            "findings": self.all_findings,
            "attack_chains": chain_result.findings,
            "remediations": remed_result.findings,
            "recon_data": recon_data,
            "rl_stats": self.rl_policy.get_stats(),
        }

        out = Path(output_dir)
        report_gen = ReportGenerator(scan_data)
        report_gen.to_json(out / "report.json")
        report_gen.to_markdown(out / "report.md")
        report_gen.to_html(out / "report.html")

        # Print summary
        console.print(f"\n[bold green]✅ Scan complete[/] in {elapsed:.1f}s\n")
        console.print(f"  📊 [bold]{len(self.all_findings)}[/] findings")
        console.print(f"  ⛓️  [bold]{len(chain_result.findings)}[/] attack chains")
        console.print(f"  🔧 [bold]{len(remed_result.findings)}[/] remediations")
        console.print(f"  🎰 RL episodes: {self.rl_policy.episode_count}")
        console.print(f"  📁 Reports: {out}/\n")

        return scan_data
