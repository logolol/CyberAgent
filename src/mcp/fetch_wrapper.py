"""
MCP-compatible web fetch wrapper for OSINT recon phase.
Replaces @modelcontextprotocol/server-fetch (not on npm).
"""
from __future__ import annotations
import logging
from typing import Optional
import requests

_log = logging.getLogger(__name__)
_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; CyberAgent/1.0; +OSINT)"
})


class FetchWrapper:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def get(self, url: str, headers: dict | None = None) -> dict:
        """Fetch a URL and return text content + metadata."""
        try:
            resp = _SESSION.get(url, headers=headers or {},
                                timeout=self.timeout, allow_redirects=True)
            return {
                "success": True, "url": resp.url,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("Content-Type",""),
                "text": resp.text[:50000],  # cap at 50KB
                "headers": dict(resp.headers),
            }
        except requests.Timeout:
            return {"success": False, "error": f"Timeout after {self.timeout}s", "url": url}
        except Exception as e:
            return {"success": False, "error": str(e), "url": url}

    def get_text(self, url: str) -> str:
        """Simplified: return just the text content."""
        result = self.get(url)
        return result.get("text", "") if result["success"] else f"ERROR: {result.get('error')}"

    def osint_search(self, query: str, engine: str = "duckduckgo") -> dict:
        """Fetch search results page for OSINT."""
        urls = {
            "duckduckgo": f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}",
            "google": f"https://www.google.com/search?q={requests.utils.quote(query)}",
        }
        return self.get(urls.get(engine, urls["duckduckgo"]))
