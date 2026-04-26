"""Local CVE cache and query interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CVEDatabase:
    """Local CVE cache for offline lookups."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or Path.home() / ".wraith" / "cve_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        cache_file = self.cache_dir / "cves.json"
        if cache_file.exists():
            try:
                self._cache = json.loads(cache_file.read_text())
            except Exception:
                self._cache = {}

    def save(self) -> None:
        cache_file = self.cache_dir / "cves.json"
        cache_file.write_text(json.dumps(self._cache, indent=2, default=str))

    def add(self, cve_id: str, data: dict[str, Any]) -> None:
        self._cache[cve_id] = data

    def get(self, cve_id: str) -> dict[str, Any] | None:
        return self._cache.get(cve_id)

    def search(self, keyword: str) -> list[dict[str, Any]]:
        results = []
        kw_lower = keyword.lower()
        for cve_id, data in self._cache.items():
            desc = data.get("description", "").lower()
            if kw_lower in cve_id.lower() or kw_lower in desc:
                results.append({"id": cve_id, **data})
        return results

    def count(self) -> int:
        return len(self._cache)
