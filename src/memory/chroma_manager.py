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

    def semantic_search(self, collection: str, query: str, n_results: int = 5) -> list[dict]:
        col = self.get_collection(collection)
        if col.count() == 0:
            return []
        try:
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
