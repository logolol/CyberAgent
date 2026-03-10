#!/usr/bin/env python3
"""Ingest SecLists metadata (NOT full wordlists) → collection: seclists_meta"""
import sys, hashlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
import chromadb
from chromadb.config import Settings

console = Console()
CHROMA_PATH = Path(__file__).parent.parent / "memory" / "chromadb"
SL_PATH = Path(__file__).parent / "SecLists"
COLLECTION = "seclists_meta"

INDEX_DIRS = ["Discovery", "Fuzzing", "Passwords/Common-Credentials",
              "Usernames", "Payloads"]

PURPOSE_MAP = {
    "Discovery": "directory and file discovery",
    "Fuzzing": "web fuzzing and injection",
    "Passwords": "password brute-force",
    "Usernames": "username enumeration",
    "Payloads": "attack payload delivery",
}

def infer_purpose(path):
    for k, v in PURPOSE_MAP.items():
        if k.lower() in str(path).lower():
            return v
    return "general pentest wordlist"

def run():
    if not SL_PATH.exists():
        console.print("[red]SecLists not cloned yet[/]")
        return 0
    client = chromadb.PersistentClient(str(CHROMA_PATH),
                                        settings=Settings(anonymized_telemetry=False))
    col = client.get_or_create_collection(COLLECTION,
                                           metadata={"hnsw:space":"cosine"})
    if col.count() > 0:
        console.print(f"[yellow]⏭ {COLLECTION} already has {col.count()} docs, skipping[/]")
        return col.count()

    docs, metas, ids = [], [], []
    for idx_dir in INDEX_DIRS:
        base = SL_PATH / idx_dir
        if not base.exists():
            continue
        for f in base.rglob("*"):
            if not f.is_file():
                continue
            try:
                line_count = sum(1 for _ in f.open("rb"))
            except Exception:
                line_count = 0
            rel = f.relative_to(SL_PATH)
            text = (f"SecLists wordlist: {f.name}\n"
                    f"Path: {rel}\n"
                    f"Lines: {line_count}\n"
                    f"Purpose: {infer_purpose(rel)}\n"
                    f"Category: {rel.parts[0]}")
            doc_id = hashlib.md5(str(rel).encode()).hexdigest()
            docs.append(text)
            metas.append({"list_name": f.name, "path": str(rel),
                           "purpose": infer_purpose(rel),
                           "line_count": str(line_count),
                           "use_case": rel.parts[0]})
            ids.append(doc_id)
            if len(docs) >= 500:
                col.add(documents=docs, metadatas=metas, ids=ids)
                docs, metas, ids = [], [], []

    if docs:
        col.add(documents=docs, metadatas=metas, ids=ids)
    console.print(f"[green]✓ {COLLECTION}:[/] {col.count()} docs")
    return col.count()

if __name__ == "__main__":
    run()
