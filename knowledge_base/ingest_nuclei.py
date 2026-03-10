#!/usr/bin/env python3
"""Ingest Nuclei YAML templates → collection: nuclei_templates"""
import sys, hashlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import chromadb
from chromadb.config import Settings

console = Console()
CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
NT_PATH = Path(__file__).parent / "nuclei-templates"
COLLECTION = "nuclei_templates"
MAX_DOCS = 20000

def run():
    if not NT_PATH.exists():
        console.print("[red]nuclei-templates not cloned yet[/]")
        return 0
    client = chromadb.PersistentClient(str(CHROMA_PATH),
                                        settings=Settings(anonymized_telemetry=False))
    col = client.get_or_create_collection(COLLECTION,
                                           metadata={"hnsw:space":"cosine"})
    if col.count() > 0:
        console.print(f"[yellow]⏭ {COLLECTION} has {col.count()} docs, skipping[/]")
        return col.count()

    yaml_files = sorted(NT_PATH.rglob("*.yaml"))[:MAX_DOCS]
    console.print(f"[cyan]Nuclei templates:[/] {len(yaml_files)} .yaml files")

    docs, metas, ids = [], [], []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), console=console) as p:
        task = p.add_task("Ingesting nuclei templates...", total=len(yaml_files))
        for f in yaml_files:
            try:
                data = yaml.safe_load(f.read_text(errors="ignore"))
                if not data or not isinstance(data, dict):
                    p.advance(task)
                    continue
                info = data.get("info", {})
                tid = data.get("id", f.stem)
                name = info.get("name", tid)
                severity = info.get("severity", "unknown")
                tags = ",".join(info.get("tags", []) or [])
                desc = info.get("description", "")
                refs = " ".join(info.get("reference", []) or [])
                protocol = str(list(data.keys())[-1]) if data else "unknown"
                text = (f"ID: {tid}\nName: {name}\nSeverity: {severity}\n"
                        f"Tags: {tags}\nDescription: {desc}\nReferences: {refs}")
                doc_id = hashlib.md5(str(f.relative_to(NT_PATH)).encode()).hexdigest()
                docs.append(text)
                metas.append({"id": tid[:200], "name": name[:200],
                               "severity": severity, "tags": tags[:200],
                               "protocol": protocol[:50]})
                ids.append(doc_id)
                if len(docs) >= 500:
                    col.add(documents=docs, metadatas=metas, ids=ids)
                    docs, metas, ids = [], [], []
            except Exception:
                pass
            p.advance(task)

    if docs:
        col.add(documents=docs, metadatas=metas, ids=ids)
    console.print(f"[green]✓ {COLLECTION}:[/] {col.count()} docs")
    return col.count()

if __name__ == "__main__":
    run()
