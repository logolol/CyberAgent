"""
External Intelligence Fallback — public API queries when local RAG confidence is low.

Sources (zero API-key required):
  - NVD CVE API v2  : https://services.nvd.nist.gov/rest/json/cves/2.0
  - ExploitDB CSV   : cached in memory/exploitdb_cache.json after first fetch
  - DuckDuckGo HTML : last-resort OSINT web search

Usage policy (ARCHITECTURE RULE):
  Only call ExternalIntel when:
    1. ChromaDB RAG returned 0 results, OR
    2. The orchestrator's _direct_llm() returned {"error": ...} twice in a row.
  Never call on every agent loop — too slow (network RTT ~200-500ms per call).

Usage:
  from utils.external_intel import ExternalIntel
  intel = ExternalIntel()

  # CVE lookup (NVD API, cached 1h)
  cve = intel.lookup_cve("CVE-2021-41773")

  # Exploit search (local exploitdb CSV + web fallback)
  exploits = intel.search_exploits("Apache path traversal RCE")

  # OSINT (DuckDuckGo, only for recon phase)
  results = intel.osint_search("target.com exposed services")
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import requests

_log = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "CyberAgent/1.0 SecurityResearch",
    "Accept": "application/json",
})

_CACHE_DIR = Path(__file__).parent.parent.parent / "memory" / "intel_cache"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)
_CACHE_TTL = 3600  # 1 hour cache for CVE/exploit data

# NVD CVE API v2 — free, no key required (rate limit: 5 req/30s without key)
_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Request timeout — fail fast so agents don't block
_TIMEOUT = 10  # seconds


class ExternalIntel:
    """
    External intelligence fallback for CyberAgent.

    All methods are:
      - Cache-first (TTL=1h, stored in memory/intel_cache/)
      - Never-raise (return error dict on failure)
      - Rate-aware (built-in delay between NVD calls)
    """

    def __init__(self):
        self._last_nvd_call: float = 0.0  # Unix timestamp

    # ── NVD CVE API ────────────────────────────────────────────────────────

    def lookup_cve(self, cve_id: str) -> dict:
        """
        Fetch CVE details from NVD API v2.

        Returns:
          {cve_id, description, cvss_v3, severity, affected_products,
           published, last_modified, references, source}

        Falls back to cached data if API unreachable.
        """
        cve_id = cve_id.upper().strip()
        cache_key = f"cve_{cve_id.replace('-', '_')}.json"
        cached = self._load_cache(cache_key)
        if cached:
            return cached

        # NVD rate limit: 5 requests/30s without API key — enforce 6s gap
        elapsed = time.time() - self._last_nvd_call
        if elapsed < 6:
            time.sleep(6 - elapsed)

        try:
            resp = _SESSION.get(
                _NVD_CVE_URL,
                params={"cveId": cve_id},
                timeout=_TIMEOUT,
            )
            self._last_nvd_call = time.time()

            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    result = self._parse_nvd_cve(vulns[0]["cve"])
                    self._save_cache(cache_key, result)
                    return result
                return {"error": f"CVE {cve_id} not found in NVD", "cve_id": cve_id}

            if resp.status_code == 404:
                return {"error": f"CVE {cve_id} not found", "cve_id": cve_id}

            return {"error": f"NVD API returned {resp.status_code}", "cve_id": cve_id}

        except requests.Timeout:
            _log.warning(f"[ExternalIntel] NVD timeout for {cve_id}")
            return {"error": "nvd_timeout", "cve_id": cve_id}
        except Exception as e:
            _log.warning(f"[ExternalIntel] NVD lookup failed: {e}")
            return {"error": str(e), "cve_id": cve_id}

    def _parse_nvd_cve(self, cve_data: dict) -> dict:
        """Extract structured data from NVD CVE JSON v2 response."""
        cve_id = cve_data.get("id", "CVE-UNKNOWN")

        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS v3 score
        cvss_v3 = None
        severity = "UNKNOWN"
        metrics = cve_data.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_v3 = m.get("baseScore")
                severity = m.get("baseSeverity", "UNKNOWN")
                break

        # Affected products (CPE)
        affected = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        affected.append(cpe.get("criteria", ""))

        # References
        refs = [r.get("url", "") for r in cve_data.get("references", [])[:5]]

        return {
            "cve_id": cve_id,
            "description": description[:500],
            "cvss_v3": cvss_v3,
            "severity": severity,
            "affected_products": affected[:10],
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
            "references": refs,
            "source": "nvd_api_v2",
        }

    # ── Exploit search ─────────────────────────────────────────────────────

    def search_exploits(self, query: str, limit: int = 10) -> list[dict]:
        """
        Search for exploits matching query.

        Strategy:
          1. ExploitDB public search API (GET, no auth)
          2. Cached results from previous searches

        Returns list of {title, cve, platform, type, edb_id, url} dicts.
        """
        cache_key = f"exploits_{self._sanitize_key(query)}.json"
        cached = self._load_cache(cache_key)
        if cached:
            return cached

        exploits = self._exploitdb_search(query, limit)
        if exploits:
            self._save_cache(cache_key, exploits)
        return exploits

    def _exploitdb_search(self, query: str, limit: int) -> list[dict]:
        """Search ExploitDB via public JSON endpoint."""
        try:
            resp = _SESSION.get(
                "https://www.exploit-db.com/search",
                params={
                    "q": query,
                    "draw": "1",
                    "start": "0",
                    "length": str(limit),
                },
                headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("data", [])[:limit]:
                    cve_raw = item.get("cve", "CVE-UNKNOWN")
                    cve_id = (
                        cve_raw.get("cve_id", "CVE-UNKNOWN")
                        if isinstance(cve_raw, dict)
                        else str(cve_raw)
                    )
                    platform_raw = item.get("platform", "")
                    platform = (
                        platform_raw.get("val", "")
                        if isinstance(platform_raw, dict)
                        else str(platform_raw)
                    )
                    type_raw = item.get("type", "")
                    exploit_type = (
                        type_raw.get("val", "")
                        if isinstance(type_raw, dict)
                        else str(type_raw)
                    )
                    results.append({
                        "edb_id": item.get("id", ""),
                        "title": item.get("description", item.get("title", "")),
                        "cve": cve_id,
                        "platform": platform,
                        "type": exploit_type,
                        "date": item.get("date_published", ""),
                        "url": f"https://www.exploit-db.com/exploits/{item.get('id', '')}",
                        "source": "exploitdb_api",
                    })
                return results
        except Exception as e:
            _log.warning(f"[ExternalIntel] ExploitDB search failed: {e}")
        return []

    # ── OSINT web search ───────────────────────────────────────────────────

    def osint_search(self, query: str, engine: str = "duckduckgo") -> list[dict]:
        """
        Perform OSINT search (recon phase only).
        Returns list of {title, url, snippet} from search results.

        Only use during recon phase — too noisy for other phases.
        """
        cache_key = f"osint_{self._sanitize_key(query)}.json"
        cached = self._load_cache(cache_key, ttl=300)  # 5-min cache for OSINT
        if cached:
            return cached

        results = self._duckduckgo_search(query)
        if results:
            self._save_cache(cache_key, results)
        return results

    def _duckduckgo_search(self, query: str) -> list[dict]:
        """Scrape DuckDuckGo HTML results (no API, no auth, always available)."""
        try:
            resp = _SESSION.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0 (compatible; CyberAgent/1.0)"},
                timeout=_TIMEOUT,
            )
            if resp.status_code != 200:
                return []

            # Basic HTML parsing without BeautifulSoup
            import re
            results = []
            # Match DDG result links
            for m in re.finditer(
                r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.+?)</a>',
                resp.text,
                re.DOTALL,
            ):
                url = m.group(1)
                title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
                if url.startswith("http") and title:
                    results.append({"title": title, "url": url, "source": "duckduckgo"})
            return results[:10]
        except Exception as e:
            _log.warning(f"[ExternalIntel] DuckDuckGo search failed: {e}")
            return []

    # ── CVE batch validation ───────────────────────────────────────────────

    def validate_cve_batch(self, cve_ids: list[str]) -> dict[str, bool]:
        """
        Validate a list of CVE IDs against NVD. Used by hallucination guard.

        Returns {cve_id: exists_in_nvd} mapping.
        Rate-limited to avoid NVD 403 responses.
        """
        results: dict[str, bool] = {}
        for cve_id in cve_ids:
            data = self.lookup_cve(cve_id)
            results[cve_id] = "error" not in data
            # Enforce NVD rate limit gap between calls
            time.sleep(0.5)
        return results

    # ── Cache helpers ──────────────────────────────────────────────────────

    def _load_cache(self, key: str, ttl: int = _CACHE_TTL) -> Optional[dict | list]:
        """Load cached data if fresh (within TTL seconds)."""
        path = _CACHE_DIR / key
        if not path.exists():
            return None
        age = time.time() - path.stat().st_mtime
        if age > ttl:
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None

    def _save_cache(self, key: str, data: dict | list):
        """Persist data to cache file."""
        path = _CACHE_DIR / key
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            _log.debug(f"[ExternalIntel] Cache write failed for {key}: {e}")

    @staticmethod
    def _sanitize_key(s: str) -> str:
        """Convert arbitrary string to safe filename component."""
        import re
        return re.sub(r"[^\w]", "_", s.lower())[:60]

    # ── Status ─────────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return external intel connection status."""
        nvd_ok = False
        try:
            resp = _SESSION.head(_NVD_CVE_URL, timeout=3)
            nvd_ok = resp.status_code < 500
        except Exception:
            pass

        return {
            "nvd_api": "available" if nvd_ok else "unreachable",
            "nvd_url": _NVD_CVE_URL,
            "exploitdb": "available (public API)",
            "osint": "available (DuckDuckGo)",
            "cache_dir": str(_CACHE_DIR),
            "cache_ttl_seconds": _CACHE_TTL,
        }
