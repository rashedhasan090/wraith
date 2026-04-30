"""Tests for evidence-backed zero-day hypothesis generation."""

from wraith_cli.knowledge.zero_day import SEVERITY_WEIGHT, ZeroDayHypothesisEngine


def _recon_data():
    return {
        "technologies": ["FastAPI"],
        "languages": {"Python": 8},
        "dependencies": [
            {"name": "openai", "version": "1.0", "ecosystem": "pypi"},
            {"name": "redis", "version": "5", "ecosystem": "pypi"},
            {"name": "pyyaml", "version": "6", "ecosystem": "pypi"},
        ],
        "entry_points": [
            {
                "file": "app/api/chat.py",
                "line": 12,
                "pattern": "@router.post",
                "code": "async def chat(message: str):",
            },
            {
                "file": "app/api/upload.py",
                "line": 28,
                "pattern": "@router.post",
                "code": "async def upload_yaml(file):",
            },
        ],
        "sensitive_files": ["app/auth.py", "app/api/chat.py", "app/cache/session_cache.py"],
        "trust_boundaries": ["user prompt to llm tool router", "tenant session cache"],
    }


def test_generates_ranked_evidence_backed_hypotheses():
    engine = ZeroDayHypothesisEngine()
    findings = [
        {
            "title": "Prompt injection can influence tool selection",
            "vuln_class": "prompt_injection",
            "severity": "high",
            "confidence": 0.8,
        }
    ]

    hypotheses = engine.generate(_recon_data(), findings, limit=5)

    assert hypotheses
    assert hypotheses == sorted(
        hypotheses,
        key=lambda item: (
            item["rigor_score"],
            item["novelty_score"],
            SEVERITY_WEIGHT[item["severity"]],
        ),
        reverse=True,
    )
    top = hypotheses[0]
    assert top["type"] == "zero_day_hypothesis"
    assert top["hypothesis_status"] == "speculative_requires_validation"
    assert top["evidence"]
    assert 0.0 <= top["rigor_score"] <= 1.0
    assert 0.0 <= top["novelty_score"] <= 1.0
    assert top["validation_safety"]["environment"].startswith("authorised")
    assert top["negative_controls"]


def test_llm_hypotheses_are_normalized_and_safely_bounded():
    engine = ZeroDayHypothesisEngine()
    normalized = engine.normalize_llm_hypotheses([
        {
            "title": "Speculative Boundary Bypass",
            "novel_class": "boundary_bypass",
            "estimated_severity": "critical",
            "confidence": 0.99,
            "validation_experiment": "Use benign fixtures to compare policy decisions.",
            "evidence": "GraphQL route and auth finding overlap.",
        }
    ])

    assert len(normalized) == 1
    hypothesis = normalized[0]
    assert hypothesis["source"] == "zero_day_llm"
    assert hypothesis["confidence"] == 0.65
    assert hypothesis["severity"] == "critical"
    assert hypothesis["evidence"] == ["GraphQL route and auth finding overlap."]
    assert "benign" in hypothesis["validation_safety"]["payload_policy"]
