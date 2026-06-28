"""CVE enrichment via the NVD 2.0 API.

Best-effort and version-based: matches by product + version keyword, attaches the
top CVEs by CVSS. Findings are *potential* (version-derived) and should be verified —
the report labels them as such. Results are cached on disk; failures degrade gracefully
(no network / rate-limited → services simply carry no CVEs)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

from ..model import CveRef, Host, Service

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE = Path.home() / ".cache" / "recon-reporter" / "cve_cache.json"


def _cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return None


def _summary(cve: dict) -> str | None:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return (d.get("value") or "")[:240]
    return None


class CveLookup:
    def __init__(self, api_key: str | None = None, max_per_service: int = 5,
                 cache_path: Path | None = None, rate_delay: float = 6.0):
        self.api_key = api_key
        self.max_per_service = max_per_service
        self.rate_delay = 0.6 if api_key else rate_delay  # NVD: 50/30s keyed, 5/30s anon
        self.cache_path = cache_path or DEFAULT_CACHE
        self.cache: dict[str, list[dict]] = {}
        self._last_call = 0.0
        self._load_cache()

    def _load_cache(self) -> None:
        try:
            self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            self.cache = {}

    def _save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")
        except Exception:
            pass

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_call
        if elapsed < self.rate_delay:
            time.sleep(self.rate_delay - elapsed)
        self._last_call = time.time()

    def _query(self, product: str, version: str) -> list[CveRef]:
        key = f"{product}|{version}".lower()
        if key in self.cache:
            rows = self.cache[key]
        else:
            try:
                self._throttle()
                headers = {"apiKey": self.api_key} if self.api_key else {}
                r = httpx.get(
                    NVD_URL,
                    params={"keywordSearch": f"{product} {version}",
                            "keywordExactMatch": "", "resultsPerPage": 20},
                    headers=headers, timeout=30,
                )
                r.raise_for_status()
                vulns = r.json().get("vulnerabilities", [])
                rows = []
                for v in vulns:
                    cve = v.get("cve", {})
                    rows.append({"id": cve.get("id"), "cvss": _cvss(cve),
                                 "summary": _summary(cve)})
                self.cache[key] = rows
                self._save_cache()
            except Exception:
                return []  # graceful: no CVEs rather than a crash
        refs = [CveRef(id=r["id"], cvss=r.get("cvss"), summary=r.get("summary"))
                for r in rows if r.get("id")]
        refs.sort(key=lambda c: c.cvss or 0, reverse=True)
        return refs[: self.max_per_service]

    def enrich(self, hosts: list[Host]) -> int:
        """Attach CVEs to every service that discloses product+version. Returns count added."""
        added = 0
        for h in hosts:
            for s in h.services:
                if s.product and s.version:
                    s.cves = self._query(s.product, s.version)
                    added += len(s.cves)
        return added
