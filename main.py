#!/usr/bin/env python3
"""
CyberAgent — Autonomous Multi-Agent Pentest Platform
Entry point. Run with:
    python3 main.py --target <ip_or_domain> [--phase full]
    python3 main.py --target 192.168.1.1 --phase recon
    python3 main.py --target 192.168.1.1 --verbose
    python3 main.py --resume <mission_id>
    python3 main.py --report-only <mission_id>
"""

import argparse
import os
import signal
import sys
from pathlib import Path

# Force unbuffered output for real-time display
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

from rich.console import Console
from rich.panel import Panel

# Make src/ importable from the project root
sys.path.insert(0, str(Path(__file__).parent / "src"))

from memory.mission_memory import MissionMemory
from agents.orchestrator_agent import OrchestratorAgent
from utils.llm_factory import warm_model

console = Console(force_terminal=True)


def print_banner():
    banner = (
        " ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗  ██████╗ ███████╗███╗   ██╗████████╗\n"
        "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝\n"
        "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   \n"
        "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   \n"
        "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   \n"
        " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝  \n\n"
        "[bold white]Multi-Agent PentestAI Platform[/] | PFE ComunikCRM\n"
        "Parrot OS | CrewAI + LangChain | Ollama Local LLM\n"
        "RAG: 147,029 docs | Tools: 4,309+ discovered"
    )
    console.print(Panel(
        banner,
        title="[bold red]CyberAgent v1.0[/]",
        border_style="red",
    ))


def check_and_update_rag():
    """
    Check if RAG databases need updating (24-hour interval).
    Skip if ChromaDB already exists or marker is fresh.
    """
    import time
    import subprocess
    
    update_marker = Path(__file__).parent / "memory" / ".last_rag_update"
    chromadb_path = Path(__file__).parent / "knowledge_base" / "chroma_db"
    
    # If ChromaDB exists, we're good - just manage the marker
    if chromadb_path.exists():
        if update_marker.exists():
            age = time.time() - update_marker.stat().st_mtime
            if age < 86400:  # 24 hours
                console.print("[dim]✓ RAG databases up-to-date (checked <24h ago)[/]")
                return
            else:
                # Marker stale but DB exists - refresh marker
                console.print("[dim]✓ RAG databases present, refreshing marker[/]")
                update_marker.touch()
                return
        else:
            # No marker but DB exists - create marker
            console.print("[dim]✓ RAG databases detected, skipping initial sync[/]")
            update_marker.touch()
            return
    
    # Only fail if ChromaDB is actually missing
    console.print("\n[bold yellow]⚠️  ChromaDB not found — RAG databases need initialization[/]")
    console.print("[dim]This is a one-time setup. Run manually:[/]")
    console.print("[bold cyan]  bash update_rag.sh[/]\n")
    console.print("[bold red]Aborting pentest — RAG knowledge required![/]")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="CyberAgent — Autonomous Multi-Agent Pentest Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 main.py --target 192.168.1.100\n"
            "  python3 main.py --target target.local --phase recon\n"
            "  python3 main.py --resume 192_168_1_100_20240101T120000\n"
            "  python3 main.py --report-only 192_168_1_100_20240101T120000\n"
        ),
    )
    parser.add_argument(
        "--target",
        help="Target domain or IP (e.g. 192.168.1.1 or target.local)",
    )
    parser.add_argument(
        "--phase",
        choices=[
            "full", "recon", "enumeration", "vuln_scan",
            "exploitation", "privesc", "postexploit", "reporting",
        ],
        default="full",
        help="Run a specific phase only (default: full chain)",
    )
    parser.add_argument(
        "--resume",
        metavar="MISSION_ID",
        help="Resume a previously interrupted mission by its ID",
    )
    parser.add_argument(
        "--report-only",
        metavar="MISSION_ID",
        dest="report_only",
        help="Generate report from a saved mission state (no new scanning)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose mode: print all LLM prompts/responses and tool calls",
    )
    args = parser.parse_args()

    # ── Set VERBOSE mode via environment variable ─────────────────────────────
    if args.verbose:
        os.environ['CA_VERBOSE'] = '1'
        console.print("[yellow]🔍 VERBOSE MODE ENABLED[/] - All LLM and tool calls will be logged")

    # Validate arguments
    if not args.target and not args.resume and not args.report_only:
        parser.error("Provide --target, --resume, or --report-only")

    print_banner()
    
    # ── Run Zero-Touch Intelligence Sync ──────────────────────────────────────
    check_and_update_rag()

    # ── Pre-warm LLM model ────────────────────────────────────────────────────
    # Load the SINGLE unified model into Ollama's RAM.
    # Using one model for all agents prevents RAM exhaustion from model swapping.
    console.print("\n[bold cyan]🔥 Pre-warming LLM model...[/]")
    warm_model("default", keep_alive="2h")   # cyberagent-pentest:7b (~5GB) - ALL agents
    console.print("[green]✓ Model ready in RAM[/]\n")

    # ── Build MissionMemory ───────────────────────────────────────────────────
    if args.resume:
        try:
            memory = MissionMemory.load_existing(args.resume)
            console.print(f"[yellow]Resuming mission:[/] {args.resume}")
        except FileNotFoundError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)
    elif args.report_only:
        try:
            memory = MissionMemory.load_existing(args.report_only)
            args.phase = "reporting"
            args.target = memory.target
            console.print(f"[yellow]Report-only mode for mission:[/] {args.report_only}")
        except FileNotFoundError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)
    else:
        memory = MissionMemory(args.target)
        console.print(f"[green]New mission started:[/] {memory.mission_id}")
        console.print(f"[cyan]Target:[/] {args.target}")
        console.print(f"[cyan]Phase:[/] {args.phase}")
        console.print(f"[cyan]State:[/] {memory.state_file}\n")

    # ── Graceful Ctrl+C ───────────────────────────────────────────────────────
    def handle_interrupt(sig, frame):
        console.print("\n[yellow]⚠  Mission paused by user.[/]")
        memory.save_state()
        console.print(
            f"[cyan]Resume with:[/] python3 main.py --resume {memory.mission_id}"
        )
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)

    # ── Run ───────────────────────────────────────────────────────────────────
    target = args.target or memory.target
    orchestrator = OrchestratorAgent(memory)
    result = orchestrator.run(target=target, phase=args.phase)

    console.print(f"\n[bold green]✅  Mission complete.[/]")
    console.print(f"[cyan]Mission ID:[/] {result['mission_id']}")
    if result.get("report_path"):
        console.print(f"[cyan]Report:[/] {result['report_path']}")
    if result.get("root_obtained"):
        console.print("[bold red]🔴  ROOT OBTAINED[/]")


if __name__ == "__main__":
    main()
