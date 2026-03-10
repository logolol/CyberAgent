#!/usr/bin/env python3
"""Ingest Linux PrivEsc checklist → collection: privesc_techniques"""
import sys, hashlib, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
import chromadb
from chromadb.config import Settings

console = Console()
CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
PRIVESC_FILE = Path(__file__).parent / "linux_privesc.md"
COLLECTION = "privesc_techniques"

def run():
    if not PRIVESC_FILE.exists():
        console.print("[red]linux_privesc.md not found[/]")
        return 0
    client = chromadb.PersistentClient(str(CHROMA_PATH),
                                        settings=Settings(anonymized_telemetry=False))
    col = client.get_or_create_collection(COLLECTION,
                                           metadata={"hnsw:space":"cosine"})
    if col.count() > 0:
        console.print(f"[yellow]⏭ {COLLECTION} has {col.count()} docs, skipping[/]")
        return col.count()

    text = PRIVESC_FILE.read_text(errors="ignore")
    # Split on ## headers
    sections = re.split(r'\n(?=#{1,3} )', text)
    docs, metas, ids = [], [], []
    for i, sec in enumerate(sections):
        sec = sec.strip()
        if len(sec) < 50:
            continue
        lines = sec.splitlines()
        technique = re.sub(r'^#+\s*', '', lines[0]).strip() if lines else f"technique_{i}"
        commands = [l for l in lines if l.strip().startswith(('$', '#', 'sudo', 'bash', 'python'))]
        doc_id = hashlib.md5(f"privesc_{i}_{technique}".encode()).hexdigest()
        docs.append(sec)
        metas.append({"technique_name": technique[:200],
                       "commands": " | ".join(commands[:5])[:500],
                       "section_idx": str(i)})
        ids.append(doc_id)

    if docs:
        col.add(documents=docs, metadatas=metas, ids=ids)
    console.print(f"[green]✓ {COLLECTION}:[/] {col.count()} docs")
    return col.count()

if __name__ == "__main__":
    run()
