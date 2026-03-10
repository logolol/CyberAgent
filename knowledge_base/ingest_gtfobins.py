#!/usr/bin/env python3
"""
Ingest GTFOBins into ChromaDB collection 'gtfobins'.

Source: https://github.com/GTFOBins/GTFOBins.github.io  (_data/gtfobins.yml)
Local clone: ~/CyberAgent/knowledge_base/gtfobins/
Target: ~/CyberAgent/memory/chromadb/  →  collection: gtfobins

Each document = one binary entry with metadata:
  binary_name, functions (shell/sudo/suid/capabilities/file_read/etc), commands
"""
import hashlib
import subprocess
import sys
from pathlib import Path

import chromadb
from chromadb.config import Settings
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

try:
    import yaml
except ImportError:
    import subprocess as _sp
    _sp.run(["pip", "install", "pyyaml"], check=True)
    import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
CHROMA_PATH = ROOT / "memory" / "chromadb"
GTFO_DIR = Path(__file__).parent / "gtfobins"
GTFO_REPO = "https://github.com/GTFOBins/GTFOBins.github.io"
COLLECTION_NAME = "gtfobins"
BATCH_SIZE = 100

console = Console()


def clone_gtfobins():
    """Clone GTFOBins repo if not present."""
    if (GTFO_DIR / "_gtfobins").exists() and any((GTFO_DIR / "_gtfobins").iterdir()):
        console.print(f"[yellow]⏭ GTFOBins already at {GTFO_DIR}[/]")
        return True

    GTFO_DIR.mkdir(parents=True, exist_ok=True)
    console.print(f"[cyan]→ Cloning GTFOBins (depth=1)...[/]")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", GTFO_REPO, str(GTFO_DIR)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            console.print(f"[green]✓ GTFOBins cloned[/]")
            return True
        else:
            console.print(f"[red]✗ Clone failed: {result.stderr}[/]")
            return False
    except Exception as e:
        console.print(f"[red]✗ Clone error: {e}[/]")
        return False


def parse_gtfobins() -> list[dict]:
    """Parse GTFOBins data from _gtfobins/ directory (one YAML file per binary)."""
    gtfo_data_dir = GTFO_DIR / "_gtfobins"
    if not gtfo_data_dir.exists():
        console.print(f"[red]✗ {gtfo_data_dir} not found[/]")
        return []

    entries = []
    binary_files = sorted(gtfo_data_dir.iterdir())

    for binary_file in binary_files:
        binary_name = binary_file.name
        try:
            with open(binary_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Strip YAML front matter delimiter if present
            content = content.lstrip("-\n").strip()
            data = yaml.safe_load(content)
        except Exception:
            continue

        if not data or not isinstance(data, dict):
            continue

        functions = data.get("functions", {})
        if not functions:
            continue

        func_names = list(functions.keys())
        func_examples = {}

        for func_name, func_list in functions.items():
            if not func_list or not isinstance(func_list, list):
                continue
            cmds = []
            for item in func_list:
                if isinstance(item, dict):
                    code = item.get("code", "")
                    description = item.get("description", "")
                    if code:
                        entry = f"# {description}\n{code}" if description else code
                        cmds.append(entry.strip())
            func_examples[func_name] = "\n".join(cmds[:3])

        entries.append(
            {
                "binary_name": binary_name,
                "functions": ", ".join(func_names),
                "func_examples": func_examples,
                "num_functions": len(func_names),
            }
        )
    return entries


def build_document(entry: dict) -> str:
    """Build searchable text for a GTFOBins entry."""
    lines = [
        f"Binary: {entry['binary_name']}",
        f"Functions: {entry['functions']}",
    ]
    for func_name, examples in entry.get("func_examples", {}).items():
        if examples:
            lines.append(f"\n[{func_name}]")
            lines.append(examples[:500])
    return "\n".join(lines)


def ingest_gtfobins(skip_if_populated: bool = True) -> int:
    """Clone GTFOBins and ingest into ChromaDB."""
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
            f"[yellow]⏭ gtfobins[/] already has {collection.count():,} docs — skipping."
        )
        return 0

    if not clone_gtfobins():
        return 0

    entries = parse_gtfobins()
    if not entries:
        console.print("[red]✗ No GTFOBins entries parsed — skipping[/]")
        return 0

    console.print(f"[cyan]→ {len(entries):,} binaries found — ingesting...[/]")

    ids, documents, metadatas = [], [], []
    inserted = 0

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Ingesting gtfobins", total=len(entries))

        for entry in entries:
            doc_id = hashlib.md5(f"gtfo:{entry['binary_name']}".encode()).hexdigest()
            ids.append(doc_id)
            documents.append(build_document(entry))
            metadatas.append(
                {
                    "binary_name": entry["binary_name"],
                    "functions": entry["functions"][:300],
                    "num_functions": str(entry["num_functions"]),
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
        f"[green]✓ gtfobins[/] — {inserted:,} binaries ingested into ChromaDB."
    )
    return inserted


if __name__ == "__main__":
    ingest_gtfobins(skip_if_populated="--force" not in sys.argv)
