"""
Reconnaissance agent — maps the attack surface.

Performs real file-system enumeration, technology fingerprinting,
entry point discovery, and dependency cataloguing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult


TECH_INDICATORS: dict[str, list[str]] = {
    "Django": ["manage.py", "settings.py", "urls.py", "wsgi.py"],
    "Flask": ["app.py", "wsgi.py"],
    "FastAPI": ["main.py"],
    "Express": ["app.js", "server.js"],
    "React": ["package.json", "src/App.jsx", "src/App.tsx"],
    "Spring": ["pom.xml", "build.gradle", "application.properties"],
    "Rails": ["Gemfile", "Rakefile", "config/routes.rb"],
    "Go": ["go.mod", "go.sum"],
    "Rust": ["Cargo.toml", "Cargo.lock"],
    "Next.js": ["next.config.js", "next.config.mjs"],
    "Laravel": ["artisan", "composer.json"],
}

EXTENSION_MAP: dict[str, str] = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".java": "Java", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".php": "PHP", ".c": "C", ".cpp": "C++", ".cs": "C#",
    ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala",
    ".jsx": "JavaScript", ".tsx": "TypeScript",
}

SENSITIVE_PATTERNS = [
    "auth", "login", "password", "secret", "token", "key",
    "admin", "payment", "billing", "crypto", "encrypt",
    "session", "cookie", "jwt", "oauth", "saml",
    "upload", "download", "exec", "eval", "system",
    "sql", "query", "database", "migrate",
    "serialize", "deserialize", "pickle", "marshal",
]

CONFIG_FILES = [
    "package.json", "requirements.txt", "Pipfile", "pyproject.toml",
    "Gemfile", "pom.xml", "build.gradle", "go.mod", "Cargo.toml",
    "composer.json", "Dockerfile", "docker-compose.yml",
    ".env", ".env.example", "Makefile",
    ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
    "terraform.tf", "serverless.yml", "nginx.conf",
]


class ReconAgent(BaseAgent):
    """Attack surface reconnaissance and technology fingerprinting."""

    name = "recon"
    description = "Maps attack surface, fingerprints technologies, identifies entry points"

    # Directories that should never be scanned (system / non-project paths)
    SYSTEM_EXCLUDE = {
        "node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build",
        ".tox", ".mypy_cache", ".pytest_cache", "egg-info", ".eggs",
        # System-level directories (avoid scanning / or ~)
        "bin", "sbin", "usr", "etc", "var", "tmp", "proc", "sys", "dev",
        "lib", "lib64", "opt", "boot", "run", "snap", "mnt", "media",
        "Library", "System", "Applications", "Volumes", "cores",
        "private", "Users", ".Trash",
        # Common non-project directories
        ".cache", ".local", ".config", ".npm", ".cargo", ".rustup",
        ".gradle", ".m2", ".ivy2", "site-packages",
    }

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        scan_config = task.get("scan_config", {})
        target = scan_config.get("target", ".")

        chain.observe(f"Starting reconnaissance of: {target}")
        target_path = Path(target).resolve()

        if not target_path.exists():
            chain.conclude(f"Target does not exist: {target_path}", confidence=1.0)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=False, errors=[f"Target not found: {target_path}"],
                reasoning_chain=chain,
            )

        # Warn if scanning a very broad directory
        if str(target_path) in ("/", os.path.expanduser("~")):
            chain.observe(f"⚠️  Broad target: {target_path} — applying smart filtering")

        custom_exclude = set(scan_config.get("exclude_patterns", []))
        exclude = self.SYSTEM_EXCLUDE | custom_exclude
        max_files = scan_config.get("max_files", 500)

        # Step 1: Enumerate files
        files = self._enumerate_files(target_path, exclude, max_files)
        chain.observe(f"Enumerated {len(files)} files")

        # Step 2: Detect languages
        lang_counts: dict[str, int] = {}
        for f in files:
            ext = Path(f).suffix.lower()
            lang = EXTENSION_MAP.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
        chain.infer(f"Languages detected: {lang_counts}")

        # Step 3: Detect technologies/frameworks
        technologies = self._detect_technologies(target_path, files)
        chain.infer(f"Technologies: {technologies}")

        # Step 4: Find entry points (routes, endpoints, handlers)
        entry_points = self._find_entry_points(files)
        chain.infer(f"Found {len(entry_points)} potential entry points")

        # Step 5: Find config and dependency files
        found_configs = self._find_configs(target_path, files)
        chain.observe(f"Config files: {list(found_configs.keys())}")

        # Step 6: Parse dependencies
        dependencies = self._parse_dependencies(found_configs)
        chain.infer(f"Found {len(dependencies)} dependencies")

        # Step 7: Identify sensitive areas (LLM-assisted)
        sensitive_files = self._find_sensitive_files(files)
        chain.infer(f"Sensitive files: {len(sensitive_files)}")

        # Step 8: LLM-assisted threat assessment
        llm_assessment = {}
        try:
            llm_assessment = await self._llm_threat_assessment(
                technologies, entry_points[:20], dependencies[:20], lang_counts,
            )
            chain.infer(f"LLM threat assessment: {llm_assessment.get('summary', 'completed')}")
        except Exception as e:
            chain.assume(f"LLM assessment unavailable: {e}")

        chain.conclude(
            f"Recon complete: {len(files)} files, {len(technologies)} technologies, "
            f"{len(entry_points)} entry points, {len(dependencies)} dependencies",
            confidence=0.9,
        )

        recon_data = {
            "target": str(target_path),
            "files_count": len(files),
            "languages": lang_counts,
            "technologies": technologies,
            "entry_points": entry_points,
            "dependencies": dependencies,
            "config_files": list(found_configs.keys()),
            "sensitive_files": sensitive_files,
            "trust_boundaries": llm_assessment.get("trust_boundaries", []),
            "llm_assessment": llm_assessment,
        }

        self.publish("recon.complete", recon_data)
        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, findings=[], data=recon_data,
            reasoning_chain=chain,
        )

    def _enumerate_files(self, root: Path, exclude: set[str], max_files: int) -> list[str]:
        """Walk the file tree, respecting exclusions."""
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for fname in filenames:
                if len(files) >= max_files:
                    return files
                fpath = os.path.join(dirpath, fname)
                files.append(fpath)
        return files

    def _detect_technologies(self, root: Path, files: list[str]) -> list[str]:
        """Detect frameworks and technologies from file indicators."""
        detected = []
        filenames = {Path(f).name for f in files}
        rel_paths = {str(Path(f).relative_to(root)) for f in files}

        for tech, indicators in TECH_INDICATORS.items():
            if any(ind in filenames or ind in rel_paths for ind in indicators):
                detected.append(tech)
        return detected

    def _find_entry_points(self, files: list[str]) -> list[dict[str, str]]:
        """Find potential entry points by scanning for route/endpoint patterns."""
        entry_points = []
        route_patterns = [
            "@app.route", "@router.", "app.get(", "app.post(", "app.put(", "app.delete(",
            "@RequestMapping", "@GetMapping", "@PostMapping",
            "func (", "http.HandleFunc", "r.GET(", "r.POST(",
            "Route::get", "Route::post",
            "def index", "def create", "def update", "def delete",
        ]
        for fpath in files:
            try:
                if not any(fpath.endswith(ext) for ext in (".py", ".js", ".ts", ".java", ".go", ".rb", ".php")):
                    continue
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read(50000)  # First 50KB
                for line_no, line in enumerate(content.split("\n"), 1):
                    for pattern in route_patterns:
                        if pattern in line:
                            entry_points.append({
                                "file": fpath,
                                "line": line_no,
                                "pattern": pattern,
                                "code": line.strip()[:200],
                            })
            except (OSError, UnicodeDecodeError):
                continue
        return entry_points

    def _find_configs(self, root: Path, files: list[str]) -> dict[str, str]:
        """Find configuration and dependency files."""
        found = {}
        filenames_map = {Path(f).name: f for f in files}
        for cfg in CONFIG_FILES:
            if cfg in filenames_map:
                found[cfg] = filenames_map[cfg]
            # Also check root-level
            root_path = root / cfg
            if root_path.exists():
                found[cfg] = str(root_path)
        return found

    def _parse_dependencies(self, configs: dict[str, str]) -> list[dict[str, str]]:
        """Parse dependencies from config files."""
        deps = []
        for name, path in configs.items():
            try:
                content = Path(path).read_text(errors="ignore")
                if name == "requirements.txt":
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split("==")
                            dep_name = parts[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
                            version = parts[1].strip() if len(parts) > 1 else ""
                            deps.append({"name": dep_name, "version": version, "ecosystem": "pypi"})
                elif name == "package.json":
                    import json
                    pkg = json.loads(content)
                    for dep_name, ver in {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.items():
                        deps.append({"name": dep_name, "version": ver, "ecosystem": "npm"})
                elif name == "pyproject.toml":
                    for line in content.splitlines():
                        line = line.strip().strip('"').strip("'").strip(",")
                        if ">=" in line or "==" in line:
                            dep_name = line.split(">=")[0].split("==")[0].split("[")[0].strip()
                            if dep_name and not dep_name.startswith("#") and not dep_name.startswith("["):
                                deps.append({"name": dep_name, "version": "", "ecosystem": "pypi"})
            except Exception:
                continue
        return deps

    def _find_sensitive_files(self, files: list[str]) -> list[str]:
        """Identify files likely to contain security-relevant code."""
        sensitive = []
        for fpath in files:
            fname_lower = fpath.lower()
            if any(pat in fname_lower for pat in SENSITIVE_PATTERNS):
                sensitive.append(fpath)
        return sensitive[:50]

    async def _llm_threat_assessment(
        self,
        technologies: list[str],
        entry_points: list[dict],
        dependencies: list[dict],
        languages: dict[str, int],
    ) -> dict[str, Any]:
        """Use LLM to assess the threat landscape."""
        system = (
            "You are a senior penetration tester performing reconnaissance. "
            "Analyse the target's technology stack and identify trust boundaries, "
            "high-risk areas, and recommended attack vectors. Respond in JSON."
        )
        user = (
            f"Technologies: {technologies}\n"
            f"Languages: {languages}\n"
            f"Entry points ({len(entry_points)} total): {entry_points[:10]}\n"
            f"Dependencies ({len(dependencies)} total): {dependencies[:10]}\n\n"
            "Provide:\n"
            '1. "trust_boundaries": list of trust boundary descriptions\n'
            '2. "high_risk_areas": list of areas to focus on\n'
            '3. "recommended_attack_vectors": list of vuln classes to prioritise\n'
            '4. "summary": one-line threat assessment\n'
        )
        return await self._call_llm_json(system, user)
