#!/usr/bin/env python3
"""
CyberAgent — Autonomous Multi-Agent Pentest Platform
Entry point. Run with:
    python3 main.py --target <ip_or_domain> [--phase full]
    python3 main.py --target 192.168.1.1 --phase recon
    python3 main.py --resume <mission_id>
    python3 main.py --report-only <mission_id>
"""

import argparse
import signal
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

# Make src/ importable from the project root
sys.path.insert(0, str(Path(__file__).parent / "src"))

from memory.mission_memory import MissionMemory
from agents.orchestrator_agent import OrchestratorAgent

console = Console()


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
    args = parser.parse_args()

    # Validate arguments
    if not args.target and not args.resume and not args.report_only:
        parser.error("Provide --target, --resume, or --report-only")

    print_banner()

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
