#!/usr/bin/env python3
"""Ingest OWASP WSTG checklist → collection: owasp"""
import sys, hashlib, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
import chromadb
from chromadb.config import Settings

console = Console()
CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
OWASP_FILE = Path(__file__).parent / "owasp_wstg.md"
COLLECTION = "owasp"

def run():
    if not OWASP_FILE.exists():
        console.print("[red]owasp_wstg.md not found[/]")
        return 0
    client = chromadb.PersistentClient(str(CHROMA_PATH),
                                        settings=Settings(anonymized_telemetry=False))
    col = client.get_or_create_collection(COLLECTION,
                                           metadata={"hnsw:space":"cosine"})
    if col.count() > 0:
        console.print(f"[yellow]⏭ {COLLECTION} has {col.count()} docs, skipping[/]")
        return col.count()

    text = OWASP_FILE.read_text(errors="ignore")
    # Split on WSTG-* identifiers
    sections = re.split(r'(?=\bWSTG-\w+)', text)
    docs, metas, ids = [], [], []
    for i, sec in enumerate(sections):
        sec = sec.strip()
        if len(sec) < 30:
            continue
        test_id_m = re.search(r'(WSTG-[\w-]+)', sec)
        test_id = test_id_m.group(1) if test_id_m else f"OWASP-{i}"
        lines = sec.splitlines()
        test_name = lines[0].strip(" #|") if lines else test_id
        doc_id = hashlib.md5(test_id.encode()).hexdigest()
        docs.append(sec)
        metas.append({"test_id": test_id, "test_name": test_name[:200]})
        ids.append(doc_id)

    if docs:
        col.add(documents=docs, metadatas=metas, ids=ids)
    console.print(f"[green]✓ {COLLECTION}:[/] {col.count()} docs")
    return col.count()

if __name__ == "__main__":
    run()
