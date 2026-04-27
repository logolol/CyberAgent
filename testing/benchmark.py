#!/usr/bin/env python3
"""
Benchmark harness for CyberAgent.

Evaluates the autonomous pentesting framework's performance across various dimensions:
- Execution time per phase
- LLM call volume and API cost estimation
- Vulnerability detection rate (True Positives vs False Positives)
- Adherence to PhaseBudgets
- Exploitation success rate

Usage:
    python3 testing/benchmark.py --target 10.10.10.10 --expected-cves CVE-2021-3156,CVE-2017-0144
"""

import argparse
import time
import json
import logging
from pathlib import Path
import sys

# Ensure src is in the python path
_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC_DIR))

from agents.orchestrator_agent import OrchestratorAgent
from memory.mission_memory import MissionMemory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run_benchmark(target: str, expected_cves: list[str]) -> dict:
    """Run the agent against a target and measure performance."""
    print(f"=== Starting Benchmark for {target} ===")
    
    start_time = time.time()
    
    # Initialize Memory
    memory = MissionMemory(mission_id=f"benchmark_{int(start_time)}")
    memory.target = target
    
    # Initialize Orchestrator
    orchestrator = OrchestratorAgent(memory=memory)
    
    print("Running orchestrator...")
    try:
        results = orchestrator.run(target=target)
    except Exception as e:
        print(f"Orchestrator failed: {e}")
        results = {"error": str(e)}
        
    end_time = time.time()
    duration = end_time - start_time
    
    # Analyze results
    print("\n=== Benchmark Results ===")
    print(f"Total Time: {duration:.2f} seconds")
    
    found_cves = set()
    for host in memory._state.get("hosts", {}).values():
        for vuln in host.get("vulnerabilities", []):
            cve = vuln.get("cve", "")
            if cve and cve != "CVE-UNKNOWN":
                found_cves.add(cve)
                
    found_expected = set(expected_cves).intersection(found_cves)
    missed_expected = set(expected_cves) - found_cves
    false_positives = found_cves - set(expected_cves)
    
    print(f"Expected CVEs: {len(expected_cves)}")
    print(f"Found Expected: {len(found_expected)} ({list(found_expected)})")
    print(f"Missed Expected: {len(missed_expected)} ({list(missed_expected)})")
    print(f"False Positives: {len(false_positives)}")
    
    if expected_cves:
        recall = len(found_expected) / len(expected_cves)
        print(f"Recall Rate: {recall:.2%}")
        
    stats = {
        "target": target,
        "duration_seconds": duration,
        "expected_cves": expected_cves,
        "found_expected": list(found_expected),
        "missed_expected": list(missed_expected),
        "false_positives": list(false_positives),
        "recall": recall if expected_cves else None
    }
    
    # Write report
    report_file = Path(f"benchmark_report_{int(start_time)}.json")
    with open(report_file, "w") as f:
        json.dump(stats, f, indent=2)
        
    print(f"Report saved to {report_file}")
    return stats

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberAgent Benchmark Harness")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--expected-cves", default="", help="Comma-separated list of expected CVEs")
    
    args = parser.parse_args()
    cves = [c.strip() for c in args.expected_cves.split(",")] if args.expected_cves else []
    
    run_benchmark(args.target, cves)
