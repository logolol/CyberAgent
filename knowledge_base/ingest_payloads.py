#!/usr/bin/env python3
"""
Ingest PayloadsAllTheThings into ChromaDB collection 'payloads'.

Source: https://github.com/swisskyrepo/PayloadsAllTheThings
Local clone: ~/CyberAgent/knowledge_base/PayloadsAllTheThings/
Target: ~/CyberAgent/memory/chromadb/  →  collection: payloads

Parses all .md files recursively.
Each document = one payload section with metadata:
  category, subcategory, technique, description, payload
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

import chromadb
from chromadb.config import Settings
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
CHROMA_PATH = ROOT / "memory" / "chromadb"
PAYLOADS_DIR = Path(__file__).parent / "PayloadsAllTheThings"
PAYLOADS_REPO = "https://github.com/swisskyrepo/PayloadsAllTheThings"
COLLECTION_NAME = "payloads"
BATCH_SIZE = 200

# Skip non-payload directories
SKIP_DIRS = {".git", "assets", "images", "CVE", ".github"}

console = Console()


def clone_payloads():
    """Clone PayloadsAllTheThings if not present."""
    if PAYLOADS_DIR.exists() and any(PAYLOADS_DIR.glob("**/*.md")):
        console.print(f"[yellow]⏭ PayloadsAllTheThings already at {PAYLOADS_DIR}[/]")
        return True

    console.print(f"[cyan]→ Cloning PayloadsAllTheThings (depth=1)...[/]")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", PAYLOADS_REPO, str(PAYLOADS_DIR)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode == 0:
            console.print(f"[green]✓ PayloadsAllTheThings cloned[/]")
            return True
        else:
            console.print(f"[red]✗ Clone failed: {result.stderr[:300]}[/]")
            # Retry
            result2 = subprocess.run(
                ["git", "clone", "--depth=1", PAYLOADS_REPO, str(PAYLOADS_DIR)],
                capture_output=True, text=True, timeout=300,
            )
            if result2.returncode == 0:
                console.print(f"[green]✓ Retry succeeded[/]")
                return True
            return False
    except Exception as e:
        console.print(f"[red]✗ Clone error: {e}[/]")
        return False


def extract_sections_from_md(md_path: Path, category: str) -> list[dict]:
    """Extract payload sections from a markdown file."""
    try:
        content = md_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    sections = []
    # Split by headings (## or ###)
    parts = re.split(r"\n(?=#{2,3}\s)", content)

    for part in parts:
        if not part.strip():
            continue
        # Extract heading
        heading_match = re.match(r"^(#{2,3})\s+(.+)", part)
        technique = heading_match.group(2).strip() if heading_match else ""

        # Extract code blocks as payloads
        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", part, re.DOTALL)
        payloads = [b.strip() for b in code_blocks if b.strip()]

        # Extract non-code text as description
        description = re.sub(r"```.*?```", "", part, flags=re.DOTALL)
        description = re.sub(r"^#{2,3}\s+.+\n", "", description).strip()[:800]

        if not (payloads or description):
            continue

        sections.append(
            {
                "category": category,
                "subcategory": md_path.stem,
                "technique": technique[:200],
                "description": description,
                "payload": "\n".join(payloads[:5])[:1000],  # keep top 5 code blocks
                "source_file": str(md_path.relative_to(PAYLOADS_DIR)),
            }
        )
    return sections


def parse_payloads() -> list[dict]:
    """Walk PayloadsAllTheThings and extract all payload sections."""
    all_sections = []
    md_files = [
        p for p in PAYLOADS_DIR.rglob("*.md")
        if not any(skip in p.parts for skip in SKIP_DIRS)
    ]

    console.print(f"[cyan]→ Found {len(md_files)} markdown files[/]")

    for md_file in md_files:
        # Category = top-level directory name
        try:
            relative = md_file.relative_to(PAYLOADS_DIR)
            category = relative.parts[0] if len(relative.parts) > 1 else "General"
        except ValueError:
            category = "General"

        sections = extract_sections_from_md(md_file, category)
        all_sections.extend(sections)

    return all_sections


def build_document(entry: dict) -> str:
    return (
        f"Category: {entry['category']}\n"
        f"Subcategory: {entry['subcategory']}\n"
        f"Technique: {entry['technique']}\n"
        f"Description: {entry['description']}\n"
        f"Payload:\n{entry['payload']}"
    )


def ingest_payloads(skip_if_populated: bool = True) -> int:
    """Clone PayloadsAllTheThings and ingest into ChromaDB."""
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
            f"[yellow]⏭ payloads[/] already has {collection.count():,} docs — skipping."
        )
        return 0

    if not clone_payloads():
        return 0

    entries = parse_payloads()
    if not entries:
        console.print("[red]✗ No payload entries found — skipping[/]")
        return 0

    console.print(f"[cyan]→ {len(entries):,} payload sections found — ingesting...[/]")

    ids, documents, metadatas = [], [], []
    inserted = 0
    seen_ids: set[str] = set()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Ingesting payloads", total=len(entries))

        for i, entry in enumerate(entries):
            doc_text = build_document(entry)
            doc_id = hashlib.md5(
                f"payload:{entry['category']}:{entry['technique']}:{i}".encode()
            ).hexdigest()

            # Deduplicate
            if doc_id in seen_ids:
                progress.advance(task)
                continue
            seen_ids.add(doc_id)

            ids.append(doc_id)
            documents.append(doc_text)
            metadatas.append(
                {
                    "category": entry["category"][:200],
                    "subcategory": entry["subcategory"][:200],
                    "technique": entry["technique"][:200],
                    "source_file": entry["source_file"][:300],
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
        f"[green]✓ payloads[/] — {inserted:,} sections ingested into ChromaDB."
    )
    return inserted


if __name__ == "__main__":
    ingest_payloads(skip_if_populated="--force" not in sys.argv)
