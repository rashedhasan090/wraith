"""Evidence-backed zero-day hypothesis generation.

This module intentionally does not produce exploit payloads. It creates
defensive research hypotheses, each with evidence, uncertainty, and safe
validation experiments that a maintainer can run in an authorised lab.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.82,
    "medium": 0.58,
    "low": 0.35,
    "info": 0.15,
}


@dataclass(frozen=True)
class HypothesisTemplate:
    """A reusable model for a likely emerging vulnerability class."""

    template_id: str
    title: str
    novel_class: str
    description: str
    base_severity: str
    affected_components: tuple[str, ...]
    technologies: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    dependency_keywords: tuple[str, ...] = ()
    entry_keywords: tuple[str, ...] = ()
    finding_classes: tuple[str, ...] = ()
    sensitive_keywords: tuple[str, ...] = ()
    evolutionary_basis: tuple[str, ...] = ()
    validation_steps: tuple[str, ...] = ()
    negative_controls: tuple[str, ...] = ()
    cwe_refs: tuple[str, ...] = ()


ZERO_DAY_TEMPLATES: tuple[HypothesisTemplate, ...] = (
    HypothesisTemplate(
        template_id="parser-differential-boundary",
        title="Parser Differential Trust Boundary Confusion",
        novel_class="parser_differential_trust_confusion",
        description=(
            "A request or document may be parsed differently by adjacent components, "
            "letting validation logic inspect one structure while execution logic "
            "consumes another."
        ),
        base_severity="high",
        affected_components=("API handlers", "file upload paths", "JSON/XML parsers"),
        technologies=("Flask", "FastAPI", "Express", "Spring", "Next.js", "Laravel"),
        languages=("Python", "JavaScript", "TypeScript", "Java", "PHP"),
        dependency_keywords=("json", "xml", "yaml", "graphql", "protobuf", "fastapi", "flask"),
        entry_keywords=("upload", "parse", "json", "xml", "graphql", "request"),
        finding_classes=("ssrf", "path_traversal", "insecure_deserialization"),
        sensitive_keywords=("upload", "download", "api", "route"),
        evolutionary_basis=(
            "HTTP request smuggling evolved from parser disagreements between proxies.",
            "XXE and deserialization CVEs show repeated failures at parser boundaries.",
        ),
        validation_steps=(
            "Build differential unit tests that feed the same benign corpus to every parser in the request path.",
            "Assert that validation and execution layers derive identical canonical fields.",
            "Add property-based tests for duplicate keys, mixed encodings, and content-type mismatches.",
        ),
        negative_controls=(
            "Confirm strict content-type enforcement rejects unsupported formats.",
            "Verify a single canonical parser is used before authorization decisions.",
        ),
        cwe_refs=("CWE-20", "CWE-436", "CWE-444"),
    ),
    HypothesisTemplate(
        template_id="async-auth-race",
        title="Asynchronous Authorization State Race",
        novel_class="async_authorization_state_race",
        description=(
            "Concurrent handlers or background jobs may observe stale identity, role, "
            "or ownership state between validation and side-effect execution."
        ),
        base_severity="high",
        affected_components=("authorization middleware", "background jobs", "admin workflows"),
        technologies=("FastAPI", "Express", "Django", "Flask", "Rails", "Go"),
        languages=("Python", "JavaScript", "TypeScript", "Go", "Ruby"),
        dependency_keywords=("celery", "rq", "bull", "sidekiq", "asyncio", "jwt", "oauth"),
        entry_keywords=("auth", "admin", "update", "delete", "payment", "webhook"),
        finding_classes=("auth_bypass", "idor", "race_condition"),
        sensitive_keywords=("auth", "admin", "session", "token", "payment"),
        evolutionary_basis=(
            "TOCTOU CVEs are moving from filesystems into distributed web state.",
            "Modern async frameworks increase interleavings around authorization checks.",
        ),
        validation_steps=(
            "Create concurrency tests that issue authorised and de-authorised requests around the same resource.",
            "Instrument authorization decisions with request IDs and compare them to commit-time ownership.",
            "Model state transitions for role changes, token revocation, and queued jobs.",
        ),
        negative_controls=(
            "Confirm side-effect code re-checks authorization using fresh state.",
            "Verify revoked tokens cannot authorize queued or retrying operations.",
        ),
        cwe_refs=("CWE-362", "CWE-367", "CWE-863"),
    ),
    HypothesisTemplate(
        template_id="llm-tool-confusion",
        title="LLM Tool Context Confusion",
        novel_class="llm_tool_context_confusion",
        description=(
            "An LLM or agent workflow may blend user-controlled content with tool "
            "instructions, causing retrieval, function calls, or policy checks to run "
            "under the wrong trust context."
        ),
        base_severity="high",
        affected_components=("LLM gateways", "tool routers", "retrieval pipelines"),
        technologies=("FastAPI", "Express", "Next.js", "Django", "Flask"),
        languages=("Python", "JavaScript", "TypeScript"),
        dependency_keywords=("openai", "anthropic", "langchain", "llamaindex", "ollama", "transformers"),
        entry_keywords=("chat", "prompt", "agent", "tool", "message", "completion"),
        finding_classes=("prompt_injection", "auth_bypass", "sensitive_data_exposure"),
        sensitive_keywords=("llm", "prompt", "chat", "agent", "tool", "secret"),
        evolutionary_basis=(
            "Prompt injection is evolving from text-only bypasses into tool authorization failures.",
            "Retrieval-augmented generation introduces new trust boundaries around documents and actions.",
        ),
        validation_steps=(
            "Add benign prompt-injection canaries and assert they never alter allowed tool sets.",
            "Unit test tool authorization separately from model output text.",
            "Trace every model-selected tool call to an explicit user/session permission grant.",
        ),
        negative_controls=(
            "Verify retrieved documents are labelled untrusted before prompt assembly.",
            "Confirm tools deny by default when model output lacks an authenticated grant.",
        ),
        cwe_refs=("CWE-20", "CWE-285", "CWE-94"),
    ),
    HypothesisTemplate(
        template_id="cache-tenant-key",
        title="Cross-Tenant Cache Key Ambiguity",
        novel_class="cross_tenant_cache_key_ambiguity",
        description=(
            "Cache keys, CDN variants, or memoized authorization results may omit tenant, "
            "locale, role, or feature-flag dimensions, leaking data across contexts."
        ),
        base_severity="high",
        affected_components=("cache layers", "CDN routes", "tenant-scoped APIs"),
        technologies=("Django", "Flask", "FastAPI", "Express", "Rails", "Next.js"),
        languages=("Python", "JavaScript", "TypeScript", "Ruby"),
        dependency_keywords=("redis", "memcached", "cache", "next", "django-cache"),
        entry_keywords=("tenant", "account", "org", "cache", "session", "profile"),
        finding_classes=("sensitive_data_exposure", "auth_bypass", "idor"),
        sensitive_keywords=("tenant", "account", "session", "cookie", "cache"),
        evolutionary_basis=(
            "Web cache deception and poisoning CVEs show cache boundaries lag behind app authorization.",
            "Multi-tenant SaaS patterns increase hidden dimensions required in cache keys.",
        ),
        validation_steps=(
            "Generate cache-key snapshots for two tenants and compare all security-relevant dimensions.",
            "Run integration tests that alternate users, roles, locales, and feature flags on the same route.",
            "Assert cached responses include no principal-specific data unless keys include principal context.",
        ),
        negative_controls=(
            "Confirm shared static assets remain cacheable without user context.",
            "Verify private responses set no-store or tenant-scoped cache keys.",
        ),
        cwe_refs=("CWE-200", "CWE-639", "CWE-524"),
    ),
    HypothesisTemplate(
        template_id="policy-data-drift",
        title="Policy/Data Model Drift Authorization Gap",
        novel_class="policy_data_model_drift",
        description=(
            "Authorization policy may be written for an older resource shape while APIs, "
            "GraphQL fields, or background jobs expose newly added relationships."
        ),
        base_severity="medium",
        affected_components=("authorization policy", "ORM models", "GraphQL schemas"),
        technologies=("Django", "Rails", "Spring", "FastAPI", "Express", "Laravel"),
        languages=("Python", "Ruby", "Java", "JavaScript", "TypeScript", "PHP"),
        dependency_keywords=("graphql", "sqlalchemy", "django", "typeorm", "prisma", "hibernate"),
        entry_keywords=("graphql", "resolver", "admin", "role", "permission", "policy"),
        finding_classes=("auth_bypass", "idor", "security_misconfiguration"),
        sensitive_keywords=("auth", "admin", "permission", "model", "schema"),
        evolutionary_basis=(
            "IDOR CVEs increasingly arise from nested relationships and autogenerated APIs.",
            "Schema-first development can outpace hand-written authorization policy.",
        ),
        validation_steps=(
            "Diff API/schema fields against policy coverage and flag fields without explicit allow/deny rules.",
            "Add object-level authorization tests for nested resources and batch endpoints.",
            "Check background jobs and admin APIs use the same policy engine as public routes.",
        ),
        negative_controls=(
            "Confirm public fields are explicitly marked public rather than implicitly allowed.",
            "Verify denied nested resources remain denied through list, detail, and batch paths.",
        ),
        cwe_refs=("CWE-639", "CWE-862", "CWE-863"),
    ),
    HypothesisTemplate(
        template_id="serialization-polyglot",
        title="Serialization Polyglot Confusion",
        novel_class="serialization_polyglot_confusion",
        description=(
            "A payload accepted as one benign serialization format may be forwarded to "
            "another decoder with richer semantics, bypassing validation assumptions."
        ),
        base_severity="high",
        affected_components=("message queues", "import/export features", "webhooks"),
        technologies=("Django", "Flask", "FastAPI", "Spring", "Express", "Go"),
        languages=("Python", "JavaScript", "TypeScript", "Java", "Go"),
        dependency_keywords=("pickle", "yaml", "xml", "protobuf", "msgpack", "avro", "serde"),
        entry_keywords=("import", "export", "webhook", "serialize", "deserialize", "upload"),
        finding_classes=("insecure_deserialization", "ssrf", "command_injection"),
        sensitive_keywords=("serialize", "deserialize", "pickle", "upload", "webhook"),
        evolutionary_basis=(
            "Deserialization CVEs recur when data crosses queue, webhook, and parser boundaries.",
            "Polyglot files and mixed content-types make format assumptions brittle.",
        ),
        validation_steps=(
            "Inventory every decode step from ingress to storage and assert exactly one trusted format transition.",
            "Fuzz benign mixed-format samples and confirm rejected inputs fail closed.",
            "Add allow-list tests for content-types and decoder combinations.",
        ),
        negative_controls=(
            "Verify safe loaders are used for YAML/XML-like formats.",
            "Confirm untrusted payloads are never passed to native object deserializers.",
        ),
        cwe_refs=("CWE-502", "CWE-20", "CWE-706"),
    ),
)


class ZeroDayHypothesisEngine:
    """Generate, score, and rank defensive zero-day hypotheses."""

    def generate(
        self,
        recon_data: dict[str, Any],
        existing_findings: list[dict[str, Any]] | None = None,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        """Return ranked hypotheses backed by target-specific evidence."""
        existing_findings = existing_findings or []
        scored = []
        for template in ZERO_DAY_TEMPLATES:
            evidence = self._collect_evidence(template, recon_data, existing_findings)
            if not evidence["items"]:
                continue
            hypothesis = self._build_hypothesis(template, evidence, existing_findings)
            scored.append(hypothesis)

        scored.sort(
            key=lambda item: (
                item["rigor_score"],
                item["novelty_score"],
                SEVERITY_WEIGHT.get(item["severity"], 0.0),
            ),
            reverse=True,
        )
        return scored[:limit]

    def normalize_llm_hypotheses(
        self,
        hypotheses: list[dict[str, Any]],
        existing_titles: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Apply the same scoring schema to LLM-provided hypotheses."""
        existing_titles = existing_titles or set()
        normalized = []
        for raw in hypotheses:
            title = str(raw.get("title") or raw.get("novel_class") or "Untitled hypothesis").strip()
            if not title or title in existing_titles:
                continue
            confidence = self._clamp_float(raw.get("confidence", 0.2), 0.05, 0.65)
            severity = self._normalize_severity(raw.get("estimated_severity") or raw.get("severity"))
            evidence = raw.get("evidence") or raw.get("evidence_chain") or []
            if isinstance(evidence, str):
                evidence = [evidence]
            validation = raw.get("validation_experiment") or raw.get("validation") or ""
            normalized.append({
                "type": "zero_day_hypothesis",
                "vuln_class": raw.get("novel_class", "llm_hypothesis"),
                "title": f"[Hypothesis] {title}",
                "severity": severity,
                "description": raw.get("description", ""),
                "affected_components": raw.get("affected_components", []),
                "evolutionary_basis": raw.get("evolutionary_basis", ""),
                "validation": validation,
                "validation_safety": self._safe_validation_policy(),
                "negative_controls": raw.get("negative_controls", []),
                "evidence": evidence,
                "confidence": confidence,
                "novelty_score": self._clamp_float(raw.get("novelty_score", 0.55), 0.0, 1.0),
                "rigor_score": self._clamp_float(raw.get("rigor_score", 0.35 + confidence * 0.4), 0.0, 1.0),
                "source": "zero_day_llm",
                "hypothesis_status": "speculative_requires_validation",
            })
        return normalized

    def _build_hypothesis(
        self,
        template: HypothesisTemplate,
        evidence: dict[str, Any],
        existing_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        evidence_score = evidence["score"]
        existing_confidence = self._finding_confidence(existing_findings, template.finding_classes)
        novelty_score = self._novelty_score(template, existing_findings, evidence)
        validation_depth = min(1.0, (len(template.validation_steps) + len(template.negative_controls)) / 6)
        rigor_score = self._round_score(
            evidence_score * 0.42
            + validation_depth * 0.24
            + novelty_score * 0.22
            + existing_confidence * 0.12
        )
        confidence = self._round_score(min(0.78, 0.18 + evidence_score * 0.42 + existing_confidence * 0.18))

        return {
            "type": "zero_day_hypothesis",
            "vuln_class": template.novel_class,
            "title": f"[Hypothesis] {template.title}",
            "severity": template.base_severity,
            "description": template.description,
            "affected_components": list(template.affected_components),
            "evolutionary_basis": list(template.evolutionary_basis),
            "validation": " ".join(template.validation_steps),
            "validation_steps": list(template.validation_steps),
            "validation_safety": self._safe_validation_policy(),
            "negative_controls": list(template.negative_controls),
            "evidence": evidence["items"],
            "evidence_summary": evidence["summary"],
            "cwe": ", ".join(template.cwe_refs),
            "confidence": confidence,
            "novelty_score": novelty_score,
            "rigor_score": rigor_score,
            "source": "zero_day",
            "hypothesis_status": "speculative_requires_validation",
        }

    def _collect_evidence(
        self,
        template: HypothesisTemplate,
        recon_data: dict[str, Any],
        existing_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        technologies = {str(t).lower() for t in recon_data.get("technologies", [])}
        languages = {str(k).lower() for k, count in recon_data.get("languages", {}).items() if count}
        dependencies = [
            str(d.get("name", "")).lower()
            for d in recon_data.get("dependencies", [])
            if isinstance(d, dict)
        ]
        entries = recon_data.get("entry_points", [])
        entry_text = " ".join(
            " ".join(str(ep.get(k, "")) for k in ("file", "pattern", "code"))
            for ep in entries
            if isinstance(ep, dict)
        ).lower()
        sensitive_text = " ".join(str(f) for f in recon_data.get("sensitive_files", [])).lower()
        trust_text = " ".join(str(t) for t in recon_data.get("trust_boundaries", [])).lower()

        items: list[dict[str, Any]] = []
        score = 0.0

        tech_matches = sorted({t for t in template.technologies if t.lower() in technologies})
        if tech_matches:
            score += 0.2
            items.append({"kind": "technology", "matches": tech_matches})

        lang_matches = sorted({l for l in template.languages if l.lower() in languages})
        if lang_matches:
            score += 0.12
            items.append({"kind": "language", "matches": lang_matches})

        dep_matches = sorted({
            kw for kw in template.dependency_keywords
            if any(kw.lower() in dep for dep in dependencies)
        })
        if dep_matches:
            score += min(0.22, 0.07 * len(dep_matches))
            items.append({"kind": "dependency", "matches": dep_matches})

        entry_matches = sorted({kw for kw in template.entry_keywords if kw.lower() in entry_text})
        if entry_matches:
            score += min(0.2, 0.05 * len(entry_matches))
            items.append({"kind": "entry_point", "matches": entry_matches, "entry_point_count": len(entries)})

        sensitive_matches = sorted({
            kw for kw in template.sensitive_keywords
            if kw.lower() in sensitive_text or kw.lower() in trust_text
        })
        if sensitive_matches:
            score += min(0.16, 0.04 * len(sensitive_matches))
            items.append({"kind": "sensitive_surface", "matches": sensitive_matches})

        finding_matches = self._matching_findings(existing_findings, template.finding_classes)
        if finding_matches:
            score += min(0.22, 0.08 * len(finding_matches))
            items.append({"kind": "prior_finding", "matches": finding_matches[:5]})

        if len(items) >= 3:
            score += 0.08

        summary = ", ".join(
            f"{item['kind']}={len(item.get('matches', []))}" for item in items
        ) or "no target-specific signals"
        return {"items": items, "score": self._round_score(min(score, 1.0)), "summary": summary}

    def _matching_findings(
        self,
        findings: list[dict[str, Any]],
        finding_classes: tuple[str, ...],
    ) -> list[str]:
        wanted = {item.lower() for item in finding_classes}
        matches = []
        for finding in findings:
            haystack = " ".join(
                str(finding.get(key, ""))
                for key in ("vuln_class", "cwe", "title", "description")
            ).lower()
            if any(item in haystack for item in wanted):
                matches.append(str(finding.get("title") or finding.get("vuln_class") or "related finding"))
        return matches

    def _finding_confidence(
        self,
        findings: list[dict[str, Any]],
        finding_classes: tuple[str, ...],
    ) -> float:
        matches = self._matching_findings(findings, finding_classes)
        if not matches:
            return 0.0
        confidences = [
            self._clamp_float(f.get("confidence", 0.5), 0.0, 1.0)
            for f in findings
            if str(f.get("title") or f.get("vuln_class") or "related finding") in matches
        ]
        if not confidences:
            return 0.45
        return self._round_score(sum(confidences) / len(confidences))

    def _novelty_score(
        self,
        template: HypothesisTemplate,
        findings: list[dict[str, Any]],
        evidence: dict[str, Any],
    ) -> float:
        existing_classes = {str(f.get("vuln_class", "")).lower() for f in findings}
        known_overlap = sum(1 for item in template.finding_classes if item.lower() in existing_classes)
        basis_bonus = min(0.18, 0.04 * len(template.evolutionary_basis))
        boundary_bonus = 0.12 if len(evidence["items"]) >= 3 else 0.04
        overlap_penalty = min(0.2, 0.06 * known_overlap)
        return self._round_score(min(1.0, max(0.15, 0.55 + basis_bonus + boundary_bonus - overlap_penalty)))

    def _safe_validation_policy(self) -> dict[str, Any]:
        return {
            "environment": "authorised test environment or local fixtures only",
            "payload_policy": "benign canaries, synthetic fixtures, and property tests; no destructive payloads",
            "network_policy": "avoid third-party targets; keep traffic scoped to owned systems",
        }

    def _normalize_severity(self, value: Any) -> str:
        severity = str(value or "medium").lower()
        if severity in SEVERITY_WEIGHT:
            return severity
        return "medium"

    def _clamp_float(self, value: Any, low: float, high: float) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = low
        return max(low, min(high, number))

    def _round_score(self, value: float) -> float:
        return round(max(0.0, min(1.0, value)), 3)
