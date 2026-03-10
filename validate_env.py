#!/usr/bin/env python3
"""
CyberAgent — Environment Validation Script
Checks all components and prints a rich status table.
"""
import os, sys, time, shutil, json
from pathlib import Path

# ── Activate venv path awareness ─────────────────────────────────────
BASE = Path(__file__).parent
sys.path.insert(0, str(BASE / "src"))

from rich.console import Console
from rich.table import Table
from rich import box
from dotenv import load_dotenv

load_dotenv(BASE / ".env")
console = Console()

PASS = "[bold green]✓ PASS[/]"
FAIL = "[bold red]✗ FAIL[/]"
WARN = "[bold yellow]⚠ WARN[/]"

results = []  # (component, detail, status)

def check(label: str, detail: str, ok: bool, warn: bool = False):
    status = PASS if ok else (WARN if warn else FAIL)
    results.append((label, detail, status))
    return ok

# ── 1. Ollama running ────────────────────────────────────────────────
try:
    import ollama
    client = ollama.Client(host=os.environ.get("OLLAMA_BASE_URL","http://localhost:11434"))
    models = [m.model for m in client.list().models]
    check("Ollama service", f"{len(models)} models loaded", True)
except Exception as e:
    check("Ollama service", str(e)[:60], False)
    models = []

# ── 2. Model pings ───────────────────────────────────────────────────
for env_key, label in [("DEFAULT_MODEL","qwen2.5 default"),
                        ("REASONING_MODEL","deepseek reasoning")]:
    model = os.environ.get(env_key,"")
    if not model:
        check(label, "Not set in .env", False); continue
    try:
        client.chat(model=model, messages=[{"role":"user","content":"ping"}],
                    options={"num_predict":1})
        check(label, model, True)
    except Exception as e:
        check(label, f"{model} — {str(e)[:50]}", False)

# ── 3. Embedding test (nomic-embed-text, 768 dims) ───────────────────
try:
    emb_model = os.environ.get("EMBEDDING_MODEL","nomic-embed-text")
    resp = client.embeddings(model=emb_model, prompt="test embedding")
    dims = len(resp.embedding)
    check("nomic-embed-text", f"{dims} dims", dims == 768)
except Exception as e:
    check("nomic-embed-text", str(e)[:60], False)

# ── 4. LLM Factory ───────────────────────────────────────────────────
try:
    from utils.llm_factory import get_llm, get_embeddings
    llm_d = get_llm("default")
    llm_r = get_llm("reasoning")
    check("LLM Factory (default)", str(llm_d.model)[:50], True)
    check("LLM Factory (reasoning)", str(llm_r.model)[:50], True)
except Exception as e:
    check("LLM Factory", str(e)[:60], False)

# ── 5. ChromaDB collections ──────────────────────────────────────────
EXPECTED_COLS = [
    "exploitdb","cve_database","mitre_attack","gtfobins","payloads",
    "hacktricks","owasp","nuclei_templates","privesc_techniques","seclists_meta"
]
total_rag_docs = 0
try:
    import chromadb
    from chromadb.config import Settings
    chroma_path = str(BASE / "memory" / "chromadb")
    cc = chromadb.PersistentClient(chroma_path, settings=Settings(anonymized_telemetry=False))
    existing = {c.name: c.count() for c in cc.list_collections()}
    for col in EXPECTED_COLS:
        count = existing.get(col, 0)
        total_rag_docs += count
        check(f"ChromaDB:{col}", f"{count:,} docs", count > 0)
    check("ChromaDB total", f"{total_rag_docs:,} docs across {len(EXPECTED_COLS)} collections",
          total_rag_docs > 100000)
except Exception as e:
    check("ChromaDB", str(e)[:60], False)

# ── 6. MissionMemory ─────────────────────────────────────────────────
try:
    from memory.mission_memory import MissionMemory
    mm = MissionMemory("validate_test.local")
    mm.add_host("10.0.0.1","test.local")
    mm.add_port("10.0.0.1", 22, "ssh", "OpenSSH_9.0")
    mm.log_action("validator","test_action","ok")
    assert mm.state_file.exists()
    assert len(mm.get_all_hosts()) == 1
    check("MissionMemory", f"state.json at {mm.state_file.parent.name}", True)
    # cleanup
    import shutil as _sh
    _sh.rmtree(mm.mission_dir, ignore_errors=True)
except Exception as e:
    check("MissionMemory", str(e)[:60], False)

# ── 7. ToolExecutor ──────────────────────────────────────────────────
try:
    from mcp.tool_executor import ToolExecutor
    te = ToolExecutor()
    found = []
    for t in ["nmap","gobuster","hydra","sqlmap","nikto","searchsploit",
              "ffuf","wpscan","john","hashcat","enum4linux","smbclient"]:
        if shutil.which(t) or (BASE/"tools"/t).exists():
            found.append(t)
    check("ToolExecutor", f"{len(found)}/12 key tools found: {','.join(found[:6])}...", len(found) >= 8)
except Exception as e:
    check("ToolExecutor", str(e)[:60], False)

# ── 8. MCP filesystem server ─────────────────────────────────────────
mcp_path = shutil.which("mcp-server-filesystem")
check("MCP filesystem server", mcp_path or "not found", bool(mcp_path), warn=not bool(mcp_path))

# ── 9. Python imports ────────────────────────────────────────────────
imports_ok = []
imports_fail = []
for pkg in ["crewai","langchain","langchain_ollama","chromadb","ollama","rich","yaml","requests","shodan"]:
    try:
        __import__(pkg)
        imports_ok.append(pkg)
    except ImportError:
        imports_fail.append(pkg)
check("Python imports", f"{len(imports_ok)}/{len(imports_ok)+len(imports_fail)} ok"
      + (f" — missing: {imports_fail}" if imports_fail else ""),
      len(imports_fail) == 0)

# ── 10. .env variables ───────────────────────────────────────────────
required_keys = ["OLLAMA_BASE_URL","DEFAULT_MODEL","REASONING_MODEL",
                 "EMBEDDING_MODEL","CHROMA_PATH","MISSIONS_PATH","REPORTS_PATH"]
missing = [k for k in required_keys if not os.environ.get(k)]
check(".env config", f"{len(required_keys)-len(missing)}/{len(required_keys)} vars set"
      + (f" — missing: {missing}" if missing else ""),
      len(missing) == 0)

# ── 11. Nuclei binary ────────────────────────────────────────────────
nuclei_path = shutil.which("nuclei")
check("nuclei binary", nuclei_path or "not in PATH", bool(nuclei_path))

# ── 12. Knowledge base files ─────────────────────────────────────────
kb_checks = [
    (BASE/"knowledge_base"/"mitre_attack.json","MITRE ATT&CK JSON"),
    (BASE/"knowledge_base"/"owasp_wstg.md","OWASP WSTG"),
    (BASE/"knowledge_base"/"linux_privesc.md","Linux PrivEsc"),
    (BASE/"knowledge_base"/"hacktricks","HackTricks clone"),
    (BASE/"knowledge_base"/"nuclei-templates","Nuclei templates"),
    (BASE/"knowledge_base"/"SecLists","SecLists"),
    (BASE/"tools"/"linpeas.sh","linpeas.sh"),
]
kb_ok = sum(1 for p,_ in kb_checks if p.exists())
check("Knowledge base files", f"{kb_ok}/{len(kb_checks)} present", kb_ok == len(kb_checks))

# ── Print table ───────────────────────────────────────────────────────
console.rule("[bold cyan]CyberAgent — Environment Validation[/]")
table = Table(box=box.ROUNDED, show_lines=True, title="Validation Results")
table.add_column("Component", style="cyan", min_width=30)
table.add_column("Detail", style="white", min_width=50)
table.add_column("Status", justify="center", min_width=10)
for comp, detail, status in results:
    table.add_row(comp, detail, status)
console.print(table)

passed = sum(1 for _,_,s in results if "PASS" in s)
warned = sum(1 for _,_,s in results if "WARN" in s)
failed = sum(1 for _,_,s in results if "FAIL" in s)
console.print(f"\n[bold]Total RAG docs:[/] [green]{total_rag_docs:,}[/]")
console.print(f"[bold]Results:[/] [green]{passed} PASS[/]  [yellow]{warned} WARN[/]  [red]{failed} FAIL[/]  "
              f"/ {len(results)} checks\n")
sys.exit(0 if failed == 0 else 1)
