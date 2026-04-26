# WRAITH — Weakness Reasoning & AI Threat Hunter

### DEF CON 2026 · Demo Labs / Tools Track

<p align="center">
<pre>
 █     █░ ██▀███   ▄▄▄       ██▓▄▄▄█████▓ ██░ ██
▓█░ █ ░█░▓██ ▒ ██▒▒████▄    ▓██▒▓  ██▒ ▓▒▓██░ ██▒
▒█░ █ ░█ ▓██ ░▄█ ▒▒██  ▀█▄  ▒██▒▒ ▓██░ ▒░▒██▀▀██░
░█░ █ ░█ ▒██▀▀█▄  ░██▄▄▄▄██ ░██░░ ▓██▓ ░ ░▓█ ░██
░░██▒██▓ ░██▓ ▒██▒ ▓█   ▓██▒░██░  ▒██▒ ░ ░▓█▒░██▓
░ ▓░▒ ▒  ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░▓    ▒ ░░    ▒ ░░▒░▒
  ▒ ░ ░    ░▒ ░ ▒░  ▒   ▒▒ ░ ▒ ░    ░     ▒ ░▒░ ░
</pre>
</p>

> **An agentic, RL-driven penetration testing framework where multiple AI agents collaboratively discover vulnerabilities through reinforcement learning and cognitive reasoning.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![DEF CON 2026](https://img.shields.io/badge/DEF%20CON-2026-red?style=flat-square)](https://defcon.org)
[![Web App](https://img.shields.io/badge/web-wraith.mdrashedulhasan.me-blueviolet?style=flat-square&logo=google-chrome)](https://wraith.mdrashedulhasan.me/)

---

## 🌐 Try It Now — Web Version

> **No installation needed.** A fully functional web version of WRAITH is live at:
>
> ### 👉 [wraith.mdrashedulhasan.me](https://wraith.mdrashedulhasan.me/)
>
> Use the web interface to run scans, view reports, and explore the RL dashboard — all from your browser. The CLI below provides the same capabilities for local / offline use.

---

## What Is WRAITH?

WRAITH is a **multi-agent LLM-powered penetration testing CLI tool** that uses **reinforcement learning** to intelligently explore attack surfaces and discover vulnerabilities. Unlike traditional scanners or simple LLM wrappers, WRAITH's agents *learn* from each scan — adapting their strategy, prioritising high-reward attack vectors, and synthesising multi-step attack chains.

### Key Innovation: RL-Driven Agentic Security Analysis

| Traditional Scanner | LLM Wrapper | **WRAITH** |
|---|---|---|
| Fixed rule matching | One-shot LLM query | Multi-agent RL exploration |
| No reasoning | No memory | Cognitive reasoning chains |
| Known vulns only | Shallow analysis | Zero-day hypothesis generation |
| No adaptation | Same every run | Learns & adapts per target |

**Novel contributions:**
1. **Reinforcement Learning Exploration** — Multi-armed bandit + epsilon-greedy strategies select which vulnerability classes to pursue, learning from reward signals (confirmed findings).
2. **Cognitive Vulnerability Reasoning (CVR)** — Five-phase methodology where agents reason through hypothesis → evidence → conclusion chains with full transparency.
3. **Multi-Agent Collaboration** — 10+ specialised agents communicate via a shared message bus, building on each other's findings in real time.
4. **Zero-Day Hypothesis Engine** — Predicts undiscovered vulnerability classes by studying CVE evolution trajectories.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/rashedhasan090/wraith.git
cd wraith
```

### 2. Set Up the Environment

```bash
# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

# Install WRAITH as a CLI tool
pip install -e .

# Verify installation
wraith --version
# wraith, version 0.3.0
```

### 3. Configure Your LLM Provider

WRAITH uses real LLM calls for semantic analysis. Pick one:

```bash
# Option A: OpenAI (default)
export OPENAI_API_KEY="sk-..."

# Option B: Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# Option C: Local Ollama (free, no API key needed)
# Make sure Ollama is running: ollama serve
# Then pass --provider ollama --model llama3 to any command
```

### 4. Run Your First Scan

```bash
# Scan a local project (source code analysis + vulnerability hunting)
wraith scan /path/to/your/project

# Scan with a live web target (enables web + API + LLM agents)
wraith scan /path/to/your/project --url https://target.example.com

# Scan using Anthropic instead of OpenAI
wraith scan /path/to/your/project --provider anthropic --model claude-sonnet-4-20250514

# Scan using local Ollama (no API key required)
wraith scan /path/to/your/project --provider ollama --model llama3
```

### 5. Try the Other Tools

```bash
# Red-team an LLM endpoint (OWASP LLM Top 10)
wraith llm-redteam https://api.example.com/chat

# OSINT reconnaissance on a domain
wraith osint example.com

# View RL agent learning statistics
wraith rl-stats

# Convert a JSON report to HTML
wraith report wraith_output/report.json --format html
```

### 6. Run the Built-in Demo (No Setup Required)

```bash
# This starts a vulnerable Flask app and runs WRAITH against it
bash demos/run_demo.sh

# Or manually:
cd demos/vulnerable_flask_app && pip install flask && python app.py &
wraith scan ../demos/vulnerable_flask_app --url http://localhost:5001 --type full
wraith llm-redteam http://localhost:5001/api/chat
```

Reports are written to `wraith_output/` by default (JSON + Markdown + HTML).

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    WRAITH Engine                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │          RL Strategy Selector                │   │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │   │
│  │  │ε-Greedy │ │ UCB1     │ │Thompson      │  │   │
│  │  │ Bandit  │ │ Selector │ │Sampling      │  │   │
│  │  └─────────┘ └──────────┘ └──────────────┘  │   │
│  │  Experience Replay Buffer → Policy Update    │   │
│  └──────────────────────────────────────────────┘   │
│                       │                             │
│  ┌────────┬──────────┬┴──────────┬──────────────┐   │
│  │ Recon  │ VulnHunt │ CVE Intel │ Zero-Day     │   │
│  │ Agent  │ Agent    │ Agent     │ Hypothesis   │   │
│  ├────────┼──────────┼──────────┼──────────────┤   │
│  │ Code   │ Attack   │ PoC Gen  │ LLM RedTeam  │   │
│  │Analyst │ Chain    │ Agent    │ Agent        │   │
│  ├────────┼──────────┼──────────┼──────────────┤   │
│  │ API    │ Remediat │ OSINT    │ Dependency   │   │
│  │Security│ Agent    │ Recon    │ Reachability │   │
│  └────────┴──────────┴──────────┴──────────────┘   │
│                       │                             │
│  ┌──────────────────────────────────────────────┐   │
│  │      Shared Message Bus (pub/sub)            │   │
│  │      Reasoning Chain Framework               │   │
│  │      Knowledge Base (CVE/NVD + patterns)     │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  Output: JSON · HTML · SARIF · Markdown · CSV       │
└─────────────────────────────────────────────────────┘
```

---

## Features

### Free Tier (5 core agents)
- **Reconnaissance** — Attack surface mapping, tech fingerprinting, entry point discovery
- **Vulnerability Hunter** — OWASP Top 10 pattern + LLM semantic analysis
- **CVE Intelligence** — NVD/CVE correlation with contextual exploitability assessment
- **Attack Chain Synthesis** — MITRE ATT&CK-mapped multi-step attack paths
- **Remediation** — Prioritised fix recommendations with code patches

### Pro Tier (all free + 5 premium agents)
- **LLM / AI Red Teaming** — Full OWASP LLM Top 10 testing suite
- **Exploit PoC Generator** — Safe, runnable proof-of-concept scripts
- **API Security Scanner** — OWASP API Top 10 (REST + GraphQL)
- **Dependency Reachability** — Proves whether vulnerable code paths are actually reachable
- **Zero-Day Hypothesis** — Predicts novel vulnerability classes from CVE evolution

### Novel: RL Exploration Engine
- **Multi-Armed Bandit** — Selects which vulnerability classes to explore based on historical reward
- **Epsilon-Greedy Exploration** — Balances exploitation of known-good strategies with exploration of new attack vectors
- **UCB1 Strategy Selection** — Upper Confidence Bound for optimal explore/exploit tradeoff
- **Thompson Sampling** — Bayesian approach to agent strategy selection
- **Experience Replay** — Stores past scan episodes for offline policy improvement
- **Adaptive Reward Shaping** — Reward signals from confirmed findings, severity, novelty

---

## How the RL Works

Traditional pentest tools follow fixed playbooks. WRAITH's agents *learn*.

```
Scan Episode:
1. Recon agent maps attack surface → state s₀
2. RL selector chooses action a (which vuln class to hunt)
3. Agent executes action → gets reward r (finding severity × confidence)
4. RL updates Q(s,a) ← Q(s,a) + α[r + γ·max Q(s',a') − Q(s,a)]
5. Next scan benefits from updated policy

After N scans:
- Agent knows that auth bypasses yield high reward in Django apps
- Agent prioritises SSRF in AWS-hosted targets
- Agent avoids low-yield patterns for specific tech stacks
```

The RL state encodes: target technology fingerprint, scan phase, findings so far, agent confidence levels. The action space covers 20+ vulnerability classes. Reward is shaped by finding severity (critical=10, high=7, medium=4, low=1) × confidence × novelty bonus.

---

## Reasoning Transparency

Every finding includes a full reasoning chain:

```
[recon] OBSERVE: Target uses Flask 2.3.2 + SQLAlchemy + JWT auth
[recon] INFER: Python web app with ORM and token-based auth
[vuln_hunter] OBSERVE: Found raw SQL in /api/search endpoint
[vuln_hunter] HYPOTHESISE: SQLi possible despite ORM — raw query bypass
[vuln_hunter] TEST: Constructed injection test for string concatenation
[vuln_hunter] CONCLUDE: Confirmed SQLi — CWE-89 — CVSS 9.8 (confidence: 0.92)
[attack_chain] OBSERVE: SQLi + JWT weak secret + admin endpoint
[attack_chain] SYNTHESISE: Chain: SQLi → extract JWT secret → forge admin token → RCE
[poc_gen] GENERATE: Python PoC script (safe: uses SLEEP timing only)
[remediation] RECOMMEND: Use parameterised queries, rotate JWT secret, add WAF rule
```

---

## CLI Reference

### Commands

| Command | Description |
|---|---|
| `wraith scan <path>` | Scan a local project directory for vulnerabilities |
| `wraith llm-redteam <url>` | Red-team test an LLM-powered endpoint (OWASP LLM Top 10) |
| `wraith osint <domain>` | OSINT reconnaissance on a domain |
| `wraith rl-stats` | Show RL agent learning statistics |
| `wraith report <path> -f <fmt>` | Convert a JSON report to another format |
| `wraith --version` | Show version |

### `wraith scan` Options

```
<path>               Target project directory to scan (required)
--url, -u            Target URL for web/API/LLM endpoint scanning
--type, -t           Scan type: full | code | web | api | llm (default: full)
--output, -o         Output directory (default: wraith_output)
--provider, -p       LLM provider: openai | anthropic | ollama (default: openai)
--model, -m          LLM model name (default: gpt-4o)
--api-key, -k        LLM API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY env var)
--ollama-url         Ollama base URL (default: http://localhost:11434)
```

### `wraith llm-redteam` Options

```
<target_url>         URL of the LLM endpoint to red-team (required)
--provider, -p       LLM provider for analysis (default: openai)
--model, -m          LLM model name
--api-key, -k        API key
--output, -o         Output directory (default: wraith_output)
```

### `wraith report` Options

```
<report_path>        Path to a JSON report file (required)
--format, -f         Output format: json | markdown | html (default: html)
--output, -o         Output file path
```

---

## Example Output

```bash
$ wraith scan code ./vulnerable-flask-app --verbose

 █     █░ ██▀███   ▄▄▄       ██▓▄▄▄█████▓ ██░ ██
▓█░ █ ░█░▓██ ▒ ██▒▒████▄    ▓██▒▓  ██▒ ▓▒▓██░ ██▒
  Weakness Reasoning & AI Threat Hunter  v0.3.0

⏳ Initialising agents...
  ✓ Recon Agent           ready
  ✓ Code Analyst          ready
  ✓ Vulnerability Hunter  ready
  ✓ CVE Intelligence      ready
  ✓ Attack Chain          ready
  ✓ Remediation           ready
  ✓ RL Explorer           ready (ε=0.15, strategy=ucb1)

🔍 Phase 1: Reconnaissance
  → Scanned 247 files across 3 languages
  → Detected: Flask 2.3.2, SQLAlchemy 2.0.23, PyJWT 2.8.0
  → Found 18 entry points, 4 trust boundaries
  → RL state encoded: [flask, sql_orm, jwt_auth, 18_endpoints]

🎯 Phase 2: RL Strategy Selection
  → UCB1 selected: sql_injection (Q=7.2, UCB=9.1)
  → UCB1 selected: auth_bypass (Q=6.8, UCB=8.4)
  → UCB1 selected: ssrf (Q=5.1, UCB=7.9)
  → Exploring: insecure_deserialization (ε-random)

🔬 Phase 3: Agent Analysis (parallel)
  [vuln_hunter] Found: SQL Injection in /api/search (CWE-89, CVSS 9.8)
  [vuln_hunter] Found: JWT Weak Secret (CWE-347, CVSS 7.5)
  [vuln_hunter] Found: Path Traversal in /download (CWE-22, CVSS 7.2)
  [cve_intel] Found: PyJWT < 2.9.0 (CVE-2024-33663, CVSS 7.4)
  [code_analyst] Found: Hardcoded DB credentials (CWE-798, CVSS 6.5)

⚡ Phase 4: Attack Chain Synthesis
  Chain 1: SQLi → DB credential dump → admin JWT forge → RCE
           Impact: CRITICAL | Likelihood: HIGH | 4 steps
  Chain 2: Path Traversal → .env file read → DB access → data exfil
           Impact: HIGH | Likelihood: MEDIUM | 3 steps

🛡️ Phase 5: Remediation
  [P1] Fix SQL injection — use parameterised queries
  [P1] Rotate JWT secret — use RS256 + key rotation
  [P2] Fix path traversal — validate file paths
  [P2] Upgrade PyJWT to 2.9.0+
  [P3] Remove hardcoded credentials — use env vars

📊 RL Update
  → sql_injection: reward=9.8, Q updated 7.2 → 7.6
  → auth_bypass: reward=7.5, Q updated 6.8 → 6.9
  → insecure_deserialization: reward=0, Q updated 3.1 → 2.8
  → Policy saved to ~/.wraith/rl_policy.json

📄 Report: wraith-report.html (5 findings, 2 chains)
   Total scan time: 34.2s | Tokens used: 12,847
```

---

## Project Structure

```
defcon-submission/
├── README.md                 ← You are here
├── SUBMISSION.md             ← DEF CON Demo Labs application
├── DEMO_GUIDE.md             ← Live demo walkthrough
├── pyproject.toml            ← Package configuration
├── requirements.txt          ← Dependencies
├── wraith_cli/
│   ├── __init__.py
│   ├── main.py               ← CLI entry point (Click + Rich)
│   ├── config.py              ← Configuration management
│   ├── engine.py              ← Core scan orchestration engine
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py            ← Base agent + message bus + memory
│   │   ├── recon.py           ← Reconnaissance agent
│   │   ├── code_analyst.py    ← Static code analysis agent
│   │   ├── vuln_hunter.py     ← Vulnerability hunter (OWASP Top 10)
│   │   ├── cve_intel.py       ← CVE/NVD intelligence agent
│   │   ├── attack_chain.py    ← MITRE ATT&CK chain synthesis
│   │   ├── remediation.py     ← Remediation recommendation agent
│   │   ├── poc_generator.py   ← Exploit PoC generation (safe)
│   │   ├── llm_redteam.py     ← LLM red teaming (OWASP LLM Top 10)
│   │   ├── api_security.py    ← API security scanner
│   │   ├── zero_day.py        ← Zero-day hypothesis engine
│   │   └── osint_recon.py     ← OSINT reconnaissance
│   ├── rl/
│   │   ├── __init__.py
│   │   ├── bandit.py          ← Multi-armed bandit (ε-greedy, UCB1, Thompson)
│   │   ├── policy.py          ← RL policy management + persistence
│   │   ├── reward.py          ← Reward shaping for vulnerability discovery
│   │   └── memory.py          ← Experience replay buffer
│   ├── reasoning/
│   │   ├── __init__.py
│   │   └── chain.py           ← Typed reasoning chains (observe→infer→conclude)
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── code.py            ← AST-based code scanner
│   │   ├── web.py             ← HTTP-based web scanner
│   │   └── dependency.py      ← Dependency/CVE scanner
│   ├── knowledge/
│   │   ├── __init__.py
│   │   ├── cve_db.py          ← NVD API v2.0 client + local cache
│   │   └── patterns.py        ← Vulnerability pattern database
│   └── reporting/
│       ├── __init__.py
│       └── report.py          ← Multi-format report generator
├── examples/
│   ├── scan_flask_app.sh
│   ├── scan_nodejs_api.sh
│   └── demo_rl_learning.py
├── demos/
│   ├── vulnerable_flask_app/  ← Intentionally vulnerable test app
│   │   ├── app.py
│   │   └── requirements.txt
│   └── run_demo.sh            ← One-command demo
└── tests/
    ├── test_agents.py
    ├── test_rl.py
    └── test_engine.py
```

---

## Research Context

WRAITH is developed by **Md Rashedul Hasan**, PhD candidate in Computer Science at the University of Nebraska-Lincoln, specialising in information security and secure software systems.

The framework builds on research at the intersection of:
- **Agentic AI** — autonomous multi-agent systems for security analysis
- **Reinforcement Learning** — reward-driven exploration of attack surfaces
- **LLM Security** — both using LLMs for security and securing LLM applications
- **Cognitive Science** — modelling how expert penetration testers reason about vulnerabilities

### Publications & Related Work
- OWASP Top 10 for LLM Applications (2025) — implemented as LLM Red Team agent
- MITRE ATT&CK Framework — attack chain classification
- NVD/CVE API v2.0 — real-time vulnerability intelligence
- CWE/CAPEC taxonomies — standardised vulnerability classification

---

## License

MIT License — see [LICENSE](../LICENSE)

## Links

| Resource | URL |
|---|---|
| 🌐 **Web App** | [wraith.mdrashedulhasan.me](https://wraith.mdrashedulhasan.me/) |
| 📦 **CLI Repo** | [github.com/rashedhasan090/wraith](https://github.com/rashedhasan090/wraith) |
| 🎬 **Demo Video** | [LinkedIn](https://www.linkedin.com/posts/mdrashedulhasan_wraith-weakness-reasoning-ai-threat-hunter-activity-7322335429753118720-qBvJ) |

## Contact

- **Author:** Md Rashedul Hasan
- **Email:** mhasan6@nebraska.edu
- **GitHub:** [@rashedhasan090](https://github.com/rashedhasan090)
- **Affiliation:** University of Nebraska-Lincoln
