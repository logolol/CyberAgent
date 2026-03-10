#!/usr/bin/env python3
"""Ingest HackTricks .md files into ChromaDB collection: hacktricks"""
import sys, hashlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import chromadb
from chromadb.config import Settings

console = Console()
CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
HT_PATH = Path(__file__).parent / "hacktricks"
COLLECTION = "hacktricks"
CHUNK_SIZE = 1200
MAX_DOCS = 15000  # cap to keep DB manageable

def chunk_text(text, size=CHUNK_SIZE):
    lines, chunks, current = text.splitlines(), [], []
    for line in lines:
        current.append(line)
        if sum(len(l) for l in current) >= size:
            chunks.append("\n".join(current))
            current = []
    if current:
        chunks.append("\n".join(current))
    return [c for c in chunks if len(c.strip()) > 50]

def run():
    if not HT_PATH.exists():
        console.print("[red]HackTricks not cloned yet[/]")
        return 0
    client = chromadb.PersistentClient(str(CHROMA_PATH),
                                        settings=Settings(anonymized_telemetry=False))
    col = client.get_or_create_collection(COLLECTION,
                                           metadata={"hnsw:space":"cosine"})
    if col.count() > 0:
        console.print(f"[yellow]⏭ {COLLECTION} already has {col.count()} docs, skipping[/]")
        return col.count()

    md_files = sorted(HT_PATH.rglob("*.md"))
    console.print(f"[cyan]HackTricks:[/] {len(md_files)} .md files found")

    docs, metas, ids = [], [], []
    total = 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), console=console) as p:
        task = p.add_task("Chunking HackTricks...", total=len(md_files))
        for f in md_files:
            if total >= MAX_DOCS:
                break
            rel = f.relative_to(HT_PATH)
            category = rel.parts[0] if len(rel.parts) > 1 else "general"
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            title = f.stem.replace("-", " ").replace("_", " ")
            for i, chunk in enumerate(chunk_text(text)):
                if total >= MAX_DOCS:
                    break
                doc_id = hashlib.md5(f"{f}_{i}".encode()).hexdigest()
                docs.append(chunk)
                metas.append({"file_path": str(rel), "title": title,
                               "category": category, "chunk_idx": i})
                ids.append(doc_id)
                total += 1
                if len(docs) >= 200:
                    col.add(documents=docs, metadatas=metas, ids=ids)
                    docs, metas, ids = [], [], []
            p.advance(task)

    if docs:
        col.add(documents=docs, metadatas=metas, ids=ids)
    console.print(f"[green]✓ {COLLECTION}:[/] {col.count()} docs ingested")
    return col.count()

if __name__ == "__main__":
    run()
