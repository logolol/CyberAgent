"""
ChromaDB manager — persistent client with RAG search across all collections.
"""
from __future__ import annotations
import logging, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import chromadb
from chromadb.config import Settings

_log = logging.getLogger(__name__)

CHROMA_PATH = Path(
    os.environ.get("CHROMA_PATH",
                   Path(__file__).parent.parent.parent / "memory" / "chromadb")
)

ALL_KNOWLEDGE_COLLECTIONS = [
    "exploitdb", "mitre_attack", "cve_database", "gtfobins",
    "payloads", "hacktricks", "owasp", "nuclei_templates",
    "privesc_techniques", "seclists_meta",
]


class ChromaManager:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else CHROMA_PATH
        self.path.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=str(self.path),
            settings=Settings(anonymized_telemetry=False),
        )

    def get_collection(self, name: str):
        return self.client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )

    def semantic_search(self, collection: str, query: str, n_results: int = 5,
                         cve_filter: str = None) -> list[dict]:
        """
        Search collection semantically, with optional CVE exact-match filter.
        
        Args:
            collection: Collection name
            query: Search query
            n_results: Max results
            cve_filter: If provided, filter results to only this CVE ID
        """
        col = self.get_collection(collection)
        if col.count() == 0:
            return []
        try:
            # Build where filter for CVE exact match if requested
            where_filter = None
            if cve_filter and cve_filter.startswith("CVE-"):
                # Try multiple metadata field names
                where_filter = {
                    "$or": [
                        {"cve_id": cve_filter},
                        {"cve": cve_filter},
                        {"CVE": cve_filter},
                    ]
                }
            
            if where_filter:
                res = col.query(
                    query_texts=[query],
                    where=where_filter,
                    n_results=min(n_results, col.count())
                )
            else:
                res = col.query(query_texts=[query], n_results=min(n_results, col.count()))
            
            results = []
            for i, doc in enumerate(res["documents"][0]):
                results.append({
                    "text": doc,
                    "metadata": res["metadatas"][0][i],
                    "distance": res["distances"][0][i] if "distances" in res else None,
                })
            return results
        except Exception as e:
            _log.error(f"semantic_search({collection}) error: {e}")
            return []
    
    def cve_lookup(self, cve_id: str, collections: list[str] = None) -> list[dict]:
        """
        Look up a specific CVE across collections with exact match.
        
        This ensures we get results for the EXACT CVE requested,
        not semantically similar but different CVEs.
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return []
        
        target_collections = collections or ["cve_database", "exploitdb", "nuclei_templates"]
        all_results = []
        
        for col_name in target_collections:
            col = self.get_collection(col_name)
            if col.count() == 0:
                continue
            
            try:
                # First try metadata filter
                for field in ["cve_id", "cve", "CVE"]:
                    try:
                        res = col.query(
                            query_texts=[cve_id],
                            where={field: cve_id},
                            n_results=10
                        )
                        if res["documents"][0]:
                            for i, doc in enumerate(res["documents"][0]):
                                all_results.append({
                                    "text": doc,
                                    "metadata": res["metadatas"][0][i],
                                    "distance": res["distances"][0][i] if "distances" in res else 0.0,
                                    "collection": col_name,
                                })
                            break
                    except Exception:
                        continue
                
                # Fallback: semantic search with CVE in query
                if not all_results:
                    res = col.query(query_texts=[cve_id], n_results=5)
                    for i, doc in enumerate(res["documents"][0]):
                        # Only include if CVE appears in text or metadata
                        meta = res["metadatas"][0][i]
                        if cve_id in doc or cve_id in str(meta.values()):
                            all_results.append({
                                "text": doc,
                                "metadata": meta,
                                "distance": res["distances"][0][i] if "distances" in res else 0.5,
                                "collection": col_name,
                            })
                            
            except Exception as e:
                _log.warning(f"cve_lookup({col_name}) error: {e}")
        
        return all_results

    def add_finding(self, collection: str, finding_dict: dict):
        col = self.get_collection(collection)
        text = finding_dict.get("text", str(finding_dict))
        meta = {k: str(v) for k, v in finding_dict.items() if k != "text"}
        ts = datetime.now(timezone.utc).isoformat()
        doc_id = f"{collection}_{ts}_{col.count()}"
        col.add(documents=[text], metadatas=[meta], ids=[doc_id])

    def get_collection_counts(self) -> dict[str, int]:
        counts = {}
        for col in self.client.list_collections():
            counts[col.name] = col.count()
        return counts

    # ── Mission-specific methods ────────────────────────────────────────
    def store_mission_finding(self, mission_id: str, agent: str,
                               finding: str, metadata: dict):
        col_name = f"mission_{mission_id}"
        self.add_finding(col_name, {
            "text": finding,
            "agent": agent,
            "mission_id": mission_id,
            **metadata,
        })

    def get_mission_context(self, mission_id: str, query: str, n: int = 10) -> list[dict]:
        col_name = f"mission_{mission_id}"
        return self.semantic_search(col_name, query, n_results=n)

    # ── Cross-collection RAG ────────────────────────────────────────────
    def get_rag_context(self, query: str,
                        collections: Optional[list[str]] = None,
                        n: int = 5) -> list[dict]:
        """
        Search across all knowledge collections and return merged ranked results.
        Agents call this for technique/exploit/CVE lookups.
        """
        if collections is None:
            collections = ALL_KNOWLEDGE_COLLECTIONS
        all_results = []
        for col_name in collections:
            try:
                hits = self.semantic_search(col_name, query, n_results=n)
                for h in hits:
                    h["source_collection"] = col_name
                    all_results.append(h)
            except Exception as e:
                _log.warning(f"RAG search in {col_name} failed: {e}")
        # Sort by distance (lower = more similar for cosine)
        all_results.sort(key=lambda x: x.get("distance") or 999)
        return all_results[:n * 2]  # return top 2*n across all collections

    # Phase-to-collection priority map: each phase hits its most relevant
    # collections first to maximise signal and minimise token usage.
    _PHASE_COLLECTIONS: dict[str, list[str]] = {
        "recon": [
            "hacktricks", "mitre_attack", "owasp", "seclists_meta",
        ],
        "enum": [
            "hacktricks", "nuclei_templates", "seclists_meta",
            "owasp", "mitre_attack",
        ],
        "vuln": [
            "cve_database", "nuclei_templates", "exploitdb",
            "owasp", "hacktricks",
        ],
        "exploit": [
            "exploitdb", "cve_database", "payloads",
            "hacktricks", "mitre_attack",
        ],
        "privesc": [
            "privesc_techniques", "gtfobins", "exploitdb",
            "mitre_attack", "hacktricks",
        ],
        "postexploit": [
            "mitre_attack", "gtfobins", "payloads",
            "hacktricks", "privesc_techniques",
        ],
        "report": [
            "cve_database", "owasp", "mitre_attack",
            "hacktricks", "exploitdb",
        ],
    }

    def get_phase_rag_context(
        self,
        phase: str,
        query: str,
        n: int = 8,
    ) -> list[dict]:
        """
        Phase-aware RAG query — searches the most relevant collections for the
        given mission phase first, then falls back to general collections.

        Args:
            phase:  Mission phase name (recon/enum/vuln/exploit/privesc/postexploit/report).
            query:  Semantic search query.
            n:      Number of results to return per collection, top 2*n returned total.

        Returns:
            Merged, distance-ranked list of hit dicts with ``source_collection`` field.
        """
        # Resolve phase → collection priority list (fall back to all collections)
        phase_key = phase.lower().replace("enumeration", "enum").replace("vuln_scan", "vuln")
        priority_cols = self._PHASE_COLLECTIONS.get(phase_key, ALL_KNOWLEDGE_COLLECTIONS)

        # Query priority collections first
        all_results: list[dict] = []
        seen_texts: set[str] = set()

        for col_name in priority_cols:
            try:
                hits = self.semantic_search(col_name, query, n_results=n)
                for h in hits:
                    # Deduplicate by first 120 chars of text
                    snippet = h["text"][:120]
                    if snippet in seen_texts:
                        continue
                    seen_texts.add(snippet)
                    h["source_collection"] = col_name
                    all_results.append(h)
            except Exception as e:
                _log.warning(f"Phase RAG search in {col_name} failed: {e}")

        # Sort by semantic distance (lower = closer match for cosine)
        all_results.sort(key=lambda x: x.get("distance") or 999)
        return all_results[: n * 2]
