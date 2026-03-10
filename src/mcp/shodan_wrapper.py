"""
Shodan free-tier wrapper — host lookup and CVE search by IP.
Requires SHODAN_API_KEY in .env.
"""
from __future__ import annotations
import logging, os

_log = logging.getLogger(__name__)


class ShodanWrapper:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self._api = None
        if self.api_key and self.api_key != "YOUR_KEY_HERE":
            try:
                import shodan
                self._api = shodan.Shodan(self.api_key)
                _log.info("Shodan API initialized")
            except ImportError:
                _log.error("shodan package not installed. Run: pip install shodan")
            except Exception as e:
                _log.error(f"Shodan init failed: {e}")

    def _require_api(self):
        if not self._api:
            raise RuntimeError(
                "Shodan API not initialized. Set SHODAN_API_KEY in .env "
                "and install shodan: pip install shodan"
            )

    def host_lookup(self, ip: str) -> dict:
        """Return Shodan data for an IP (ports, vulns, banners, org)."""
        self._require_api()
        try:
            result = self._api.host(ip)
            return {
                "ip": result.get("ip_str"),
                "org": result.get("org"),
                "os": result.get("os"),
                "ports": result.get("ports", []),
                "vulns": list(result.get("vulns", {}).keys()),
                "hostnames": result.get("hostnames", []),
                "tags": result.get("tags", []),
                "raw": result,
            }
        except Exception as e:
            _log.error(f"Shodan host_lookup({ip}): {e}")
            return {"error": str(e)}

    def cve_search(self, cve_id: str) -> dict:
        """Search Shodan for hosts affected by a specific CVE."""
        self._require_api()
        try:
            results = self._api.search(f"vuln:{cve_id}")
            return {
                "total": results.get("total", 0),
                "hosts": [
                    {"ip": m.get("ip_str"), "port": m.get("port"),
                     "org": m.get("org"), "country": m.get("location", {}).get("country_name")}
                    for m in results.get("matches", [])[:20]
                ],
            }
        except Exception as e:
            _log.error(f"Shodan cve_search({cve_id}): {e}")
            return {"error": str(e)}

    def search(self, query: str, max_results: int = 20) -> dict:
        """Generic Shodan search query (free tier: 100 results/month)."""
        self._require_api()
        try:
            results = self._api.search(query)
            return {
                "total": results.get("total", 0),
                "matches": results.get("matches", [])[:max_results],
            }
        except Exception as e:
            _log.error(f"Shodan search({query!r}): {e}")
            return {"error": str(e)}
