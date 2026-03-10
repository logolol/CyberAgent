#!/usr/bin/env python3
"""
Ingest MITRE ATT&CK Enterprise into ChromaDB collection 'mitre_attack'.

Source: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
Local:  ~/CyberAgent/knowledge_base/mitre_attack.json
Target: ~/CyberAgent/memory/chromadb/  →  collection: mitre_attack

Each document = one ATT&CK technique with metadata:
  technique_id, name, tactic(s), description, platforms, detection, url
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import chromadb
from chromadb.config import Settings
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

# ── Paths & constants ─────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
CHROMA_PATH = ROOT / "memory" / "chromadb"
MITRE_JSON = Path(__file__).parent / "mitre_attack.json"
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
COLLECTION_NAME = "mitre_attack"
BATCH_SIZE = 100

console = Console()


def download_mitre():
    """Download MITRE ATT&CK JSON if not already present."""
    if MITRE_JSON.exists() and MITRE_JSON.stat().st_size > 1_000_000:
        console.print(f"[yellow]⏭ MITRE JSON already at {MITRE_JSON}[/]")
        return True

    console.print(f"[cyan]→ Downloading MITRE ATT&CK Enterprise JSON...[/]")
    try:
        urllib.request.urlretrieve(MITRE_URL, MITRE_JSON)
        console.print(
            f"[green]✓ Downloaded[/] — {MITRE_JSON.stat().st_size / 1e6:.1f} MB"
        )
        return True
    except Exception as e:
        console.print(f"[red]✗ Download failed: {e}[/]")
        # Retry once
        try:
            urllib.request.urlretrieve(MITRE_URL, MITRE_JSON)
            console.print(f"[green]✓ Retry succeeded[/]")
            return True
        except Exception as e2:
            console.print(f"[red]✗ Retry also failed: {e2} — skipping MITRE[/]")
            return False


def parse_techniques(data: dict) -> list[dict]:
    """Extract technique entries from the STIX bundle."""
    techniques = []
    objects = data.get("objects", [])

    # Build tactic lookup: phase-name → tactic name
    tactic_map = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            tactic_map[short] = name

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        # Technique ID
        ext_refs = obj.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "T????",
        )
        url = next(
            (r.get("url", "") for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )

        # Tactics (kill-chain phases)
        phases = obj.get("kill_chain_phases", [])
        tactics = [tactic_map.get(p["phase_name"], p["phase_name"]) for p in phases]

        description = obj.get("description", "")[:2000]
        platforms = obj.get("x_mitre_platforms", [])
        detection = obj.get("x_mitre_detection", "")[:1000]
        data_sources = obj.get("x_mitre_data_sources", [])

        techniques.append(
            {
                "technique_id": tech_id,
                "name": obj.get("name", ""),
                "tactics": ", ".join(tactics),
                "description": description,
                "platforms": ", ".join(platforms),
                "detection": detection,
                "data_sources": ", ".join(data_sources[:5]),
                "url": url,
            }
        )

    return techniques


def build_document(tech: dict) -> str:
    """Build searchable text from a technique dict."""
    return (
        f"Technique ID: {tech['technique_id']}\n"
        f"Name: {tech['name']}\n"
        f"Tactics: {tech['tactics']}\n"
        f"Platforms: {tech['platforms']}\n"
        f"Description: {tech['description']}\n"
        f"Detection: {tech['detection']}\n"
        f"Data Sources: {tech['data_sources']}"
    )


def ingest_mitre(skip_if_populated: bool = True) -> int:
    """Download and ingest MITRE ATT&CK into ChromaDB.

    Returns:
        Number of documents ingested.
    """
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(
        path=str(CHROMA_PATH),
        settings=Settings(anonymized_telemetry=False),
    )
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    if skip_if_populated and collection.count() > 0:
        console.print(
            f"[yellow]⏭ mitre_attack[/] already has {collection.count():,} docs — skipping."
        )
        return 0

    if not download_mitre():
        return 0

    console.print(f"[cyan]→ Parsing MITRE ATT&CK JSON...[/]")
    with open(MITRE_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = parse_techniques(data)
    console.print(f"[cyan]→ {len(techniques):,} techniques found — ingesting...[/]")

    ids, documents, metadatas = [], [], []
    inserted = 0

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Ingesting mitre_attack", total=len(techniques))

        for i, tech in enumerate(techniques):
            doc_id = hashlib.md5(f"mitre:{tech['technique_id']}".encode()).hexdigest()
            ids.append(doc_id)
            documents.append(build_document(tech))
            metadatas.append(
                {
                    "technique_id": tech["technique_id"],
                    "name": tech["name"][:200],
                    "tactics": tech["tactics"][:200],
                    "platforms": tech["platforms"][:200],
                    "detection": tech["detection"][:400],
                    "url": tech["url"],
                }
            )

            if len(ids) >= BATCH_SIZE:
                collection.add(ids=ids, documents=documents, metadatas=metadatas)
                inserted += len(ids)
                ids, documents, metadatas = [], [], []

            progress.advance(task)

        if ids:
            collection.add(ids=ids, documents=documents, metadatas=metadatas)
            inserted += len(ids)

    console.print(
        f"[green]✓ mitre_attack[/] — {inserted:,} techniques ingested into ChromaDB."
    )
    return inserted


if __name__ == "__main__":
    ingest_mitre(skip_if_populated="--force" not in sys.argv)
