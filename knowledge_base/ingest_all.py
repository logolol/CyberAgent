#!/usr/bin/env python3
"""Master ingestion script — runs all knowledge base ingest scripts."""
import sys, importlib, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

SCRIPTS = [
    ("exploitdb",          "ingest_exploitdb"),
    ("mitre_attack",       "ingest_mitre"),
    ("cve_database",       "ingest_cve"),
    ("gtfobins",           "ingest_gtfobins"),
    ("payloads",           "ingest_payloads"),
    ("hacktricks",         "ingest_hacktricks"),
    ("seclists_meta",      "ingest_seclists"),
    ("owasp",              "ingest_owasp"),
    ("nuclei_templates",   "ingest_nuclei"),
    ("privesc_techniques", "ingest_privesc"),
]

def run():
    console.rule("[bold cyan]CyberAgent — Full Knowledge Base Ingest[/]")
    results = []
    total_docs = 0

    for col_name, module_name in SCRIPTS:
        console.print(f"\n[bold cyan]▶ Ingesting:[/] {col_name}")
        t0 = time.time()
        try:
            mod = importlib.import_module(module_name)
            force = "--force" in sys.argv
            
            # Auto-detect the right function (run, or ingest_*)
            func = getattr(mod, "run", None)
            if not func:
                for attr in dir(mod):
                    if attr.startswith("ingest_") and callable(getattr(mod, attr)):
                        func = getattr(mod, attr)
                        break
            
            if not func:
                raise ValueError(f"No entry point found in {module_name}")
                
            import inspect
            sig = inspect.signature(func)
            if "skip_if_populated" in sig.parameters:
                count = func(skip_if_populated=not force)
            else:
                count = func()
                
            elapsed = time.time() - t0
            results.append((col_name, count or 0, elapsed, "✓"))
            total_docs += count or 0
        except Exception as e:
            elapsed = time.time() - t0
            console.print(f"[red]✗ {col_name}: {e}[/]")
            results.append((col_name, 0, elapsed, "✗"))

    # Summary table
    table = Table(title=f"Knowledge Base Summary — {total_docs:,} total docs")
    table.add_column("Collection", style="cyan")
    table.add_column("Documents", justify="right", style="green")
    table.add_column("Time", justify="right")
    table.add_column("Status", justify="center")
    for col, count, elapsed, status in results:
        table.add_row(col, f"{count:,}", f"{elapsed:.1f}s",
                      f"[green]{status}[/]" if status=="✓" else f"[red]{status}[/]")
    console.print(table)
    console.print(f"\n[bold green]Total:[/] {total_docs:,} documents across {len(results)} collections")

if __name__ == "__main__":
    run()
