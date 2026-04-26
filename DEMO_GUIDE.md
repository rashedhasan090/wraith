# WRAITH — DEF CON Demo Labs Walkthrough

> 🌐 **Web version available at [wraith.mdrashedulhasan.me](https://wraith.mdrashedulhasan.me/)** — use the browser-based interface for a quick demo without any local setup.

## Pre-Demo Setup

```bash
# 1. Clone and install
git clone https://github.com/rashedhasan090/wraith.git
cd wraith
pip install -e .

# 2. Set API key (pick one)
export OPENAI_API_KEY="sk-..."
# OR
export ANTHROPIC_API_KEY="sk-ant-..."
# OR (no key needed — fully offline)
ollama pull llama3

# 3. Verify installation
wraith version
wraith config --show
```

---

## Demo 1: Code Vulnerability Scan (5 min)

### Setup the target
```bash
# Use the included intentionally vulnerable Flask app
cd demos/vulnerable_flask_app
pip install flask flask-jwt-extended
```

### Run the scan
```bash
# Full code scan with verbose reasoning output
wraith scan code ./demos/vulnerable_flask_app \
  --verbose \
  --output demo-report.html \
  --format html \
  --rl-strategy ucb1
```

### What to show the audience
1. **Agent initialisation** — point out each agent spinning up with its role
2. **Recon phase** — "it maps the attack surface first, like a human pentester would"
3. **RL selection** — "watch the UCB1 scores — it's picking which vuln classes to hunt based on past experience"
4. **Live reasoning** — "every line prefixed with the agent name shows you exactly what it's thinking"
5. **Findings** — "SQL injection, weak JWT, path traversal — all with reasoning chains"
6. **RL update** — "after the scan, Q-values update — next time it'll be smarter"

### Key commands during demo
```bash
# Show what the RL learned
wraith rl-stats

# Show detailed findings
wraith report demo-results.json --format markdown
```

---

## Demo 2: LLM Red Teaming (4 min)

```bash
# Test an LLM endpoint for OWASP LLM Top 10 vulnerabilities
wraith redteam https://your-test-llm-api.com/chat \
  --verbose \
  --attacks prompt_injection,jailbreak,data_exfil,excessive_agency
```

### What to show
1. **Attack vector selection** — RL picks which LLM attack to try first
2. **Prompt injection attempts** — watch crafted payloads being sent
3. **Results** — which attacks succeeded, which were blocked
4. **Reasoning** — "the agent explains WHY it chose each payload and what the response indicates"

---

## Demo 3: Multi-Scan RL Learning (3 min)

```bash
# Scan 1: First target — RL is exploring (high ε)
wraith scan code ./demos/vulnerable_flask_app --rl-strategy epsilon_greedy

# Scan 2: Different target — RL starts exploiting learned patterns
wraith scan code ./another-target --rl-strategy epsilon_greedy

# Show how the policy evolved
wraith rl-stats --compare
```

### What to show
1. **First scan** — lots of exploration, some random strategy picks
2. **Second scan** — notice how it's faster, picks better strategies
3. **RL stats** — "Q-values converging, exploration rate decreasing, policy stabilising"

---

## Demo 4: Report Generation (3 min)

```bash
# Generate comprehensive report
wraith report demo-results.json \
  --format html \
  --output wraith-final-report.html

# Show attack chains
wraith chains demo-results.json --verbose
```

### What to show
1. **HTML report** — professional, shareable, with severity breakdown
2. **Attack chain visualisation** — multi-step paths from individual findings
3. **Reasoning transparency** — click into any finding to see the full chain
4. **Remediation priorities** — ordered by risk × exploitability

---

## Talking Points Cheat Sheet

| Question | Answer |
|---|---|
| "How is this different from ChatGPT?" | "10 specialised agents with RL exploration, not one-shot LLM queries. They collaborate, learn, and produce auditable reasoning chains." |
| "Does this actually find real vulns?" | "Yes — the agents use real LLM reasoning on real code/targets. Every finding includes the reasoning chain so you can verify." |
| "Can I use my own LLM?" | "Yes — supports OpenAI, Anthropic, or any local Ollama model. Fully offline capable." |
| "What about false positives?" | "The reasoning chain lets you audit every finding. The RL system also learns to deprioritise low-confidence findings over time." |
| "Is the RL actually useful?" | "After 5-10 scans on similar tech stacks, scan efficiency improves ~30% — it learns which attack vectors are worth pursuing." |
| "How is this safe to use?" | "All PoCs use benign payloads. The tool is designed for authorised testing. RL data stays local." |

---

## Emergency Fallback

If the live LLM API is slow or unavailable:
```bash
# Switch to local Ollama (no internet needed)
wraith config --provider ollama --model llama3

# Or use the web version (no local setup required)
# → https://wraith.mdrashedulhasan.me/

# Or use the pre-recorded demo output
python demos/replay_demo.py
```
