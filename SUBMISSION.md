# DEF CON 32 — Demo Labs Application

## Tool Name
**WRAITH** — Weakness Reasoning & AI Threat Hunter

## Version
0.3.0-defcon

## Category
Offensive Security / AI-Assisted Penetration Testing

## One-Line Description
Multi-agent LLM penetration testing framework that uses reinforcement learning to autonomously explore attack surfaces, discover vulnerabilities, and synthesise attack chains — with full reasoning transparency.

---

## Tool Description (200 words)

WRAITH is an open-source CLI-based penetration testing framework that deploys 10+ specialised AI agents (powered by GPT-4o, Claude, or local Ollama models) to collaboratively discover security vulnerabilities. What makes WRAITH unique is its **reinforcement learning exploration engine** — agents don't follow static playbooks. Instead, a multi-armed bandit algorithm (ε-greedy, UCB1, or Thompson Sampling) selects which vulnerability classes to pursue based on reward signals from past scans. Over time, WRAITH learns that certain attack vectors yield higher rewards for specific technology stacks, making each subsequent scan more efficient and effective.

The framework introduces **Cognitive Vulnerability Reasoning (CVR)**, a five-phase methodology modelling how expert pentesters think: contextual understanding → threat modelling → semantic taint analysis → logic flaw detection → cross-cutting analysis. Every finding includes a full, auditable reasoning chain showing exactly how it was discovered.

WRAITH covers the complete offensive lifecycle: reconnaissance, code analysis, vulnerability hunting (OWASP Top 10), CVE intelligence (NVD API), attack chain synthesis (MITRE ATT&CK), exploit PoC generation (safe payloads only), LLM/AI red teaming (OWASP LLM Top 10), API security scanning, and automated remediation recommendations.

---

## Target Audience
- Penetration testers seeking AI-augmented offensive tools
- Security researchers exploring agentic AI for vulnerability discovery
- Red team operators looking for automated attack chain synthesis
- AI/ML security practitioners testing LLM applications
- Bug bounty hunters wanting RL-guided exploration

## Technical Requirements
- Python 3.10+
- LLM API key (OpenAI, Anthropic) or local Ollama instance
- 4GB RAM minimum
- Internet connection for CVE database queries (offline mode available)
- No special hardware required — runs on a laptop

---

## What Will You Demonstrate?

### Live Demo Plan (15-minute slot)

**Demo 1: Code Scan with RL Learning (5 min)**
1. Scan an intentionally vulnerable Flask application using `wraith scan code`
2. Show agents reasoning in real time — each agent's observations, hypotheses, conclusions visible in the terminal
3. Watch the RL explorer select vulnerability classes based on UCB1 scores
4. View the generated attack chains (SQL injection → credential dump → admin access)
5. Show the RL policy updating after the scan — Q-values changing in real time

**Demo 2: LLM Red Teaming (4 min)**
1. Run `wraith redteam` against a test LLM endpoint
2. Watch the agent cycle through OWASP LLM Top 10 attack vectors
3. See prompt injection, jailbreak, and data exfiltration attempts with live results
4. Show how the RL strategy adapts — successful attack vectors get higher reward

**Demo 3: Multi-Scan Learning (3 min)**
1. Run WRAITH against 3 different targets in sequence
2. Show `wraith rl-stats` — demonstrate how the policy evolves
3. Third scan is faster and finds more because the RL policy has learned from previous scans
4. Show the experience replay buffer and policy convergence

**Demo 4: Full Report + Attack Graph (3 min)**
1. Generate an HTML report with interactive attack graph visualisation
2. Walk through a critical attack chain with full reasoning transparency
3. Show the remediation recommendations with prioritised fix order

### Key Demo Talking Points
- "Every finding includes a reasoning chain — you can audit exactly how the AI reached its conclusion"
- "The RL exploration means the tool gets smarter with each scan — watch the Q-values update"
- "This isn't an LLM wrapper — it's 10 specialised agents that collaborate through a shared message bus"
- "Zero-day hypothesis engine predicts where new vulnerability classes will emerge"

---

## Novelty

### What's New?
1. **First pentest tool with RL-driven vulnerability exploration** — agents learn which attack vectors to prioritise per technology stack, improving scan efficiency over time
2. **Cognitive Vulnerability Reasoning** — structured, auditable reasoning methodology for AI-discovered findings (not just "LLM said so")
3. **Multi-agent collaboration with message bus** — agents build on each other's findings (recon informs vuln hunting, which informs attack chain synthesis)
4. **Zero-day hypothesis generation** — predicts undiscovered vulnerability classes from CVE evolutionary trajectories

### How Is This Different From Existing Tools?
| Tool | Approach | WRAITH Advantage |
|---|---|---|
| Semgrep/CodeQL | Static pattern matching | Semantic reasoning + logic flaw detection |
| Burp Suite + AI | Single-model wrapper | Multi-agent collaboration + RL learning |
| PentestGPT | LLM conversation guidance | Autonomous agents + automated execution |
| Nuclei | Template-based scanning | RL-guided template selection + novel discovery |
| HackerOne AI | Bug triage assistance | Active vulnerability hunting + PoC generation |

---

## Author Information

**Md Rashedul Hasan**
- PhD Candidate, Computer Science, University of Nebraska-Lincoln
- Research: Information Security, Secure Software Systems, Agentic AI
- CrowdSource Researcher @ Detectify
- Verified Information Security Researcher (ICT Division, Government of Bangladesh)
- Co-founder, CyberTrendz Inc. (Grameenphone Accelerator top 27)

**Contact:**
- Email: mhasan6@nebraska.edu
- GitHub: github.com/rashedhasan090
- LinkedIn: linkedin.com/in/rashedhasan090

---

## Open Source
- **Repository:** https://github.com/rashedhasan090/wraith
- **Web App:** https://wraith.mdrashedulhasan.me/
- **License:** MIT
- **Language:** Python
- **LOC:** ~4,000+ (CLI tool) + framework

## Previous Presentations
First public presentation — this would be WRAITH's debut at DEF CON.

## Additional Notes
- The tool is designed for **authorised security testing only**
- All exploit PoCs use **safe, non-destructive payloads** (timing-based SQLi, benign marker XSS, read-only IDOR)
- The RL exploration can run fully **offline** with local Ollama models (no data leaves the machine)
- Attendees can install and try WRAITH during the demo on their own laptops
