"""
OrchestratorAgent — THE BRAIN of CyberAgent.

Controls the entire pentest mission lifecycle:
  - Builds target intelligence briefings for each specialist agent
  - Enforces phase gate conditions before advancing
  - Analyzes each agent's output and adapts the attack strategy
  - Uses DeepSeek-R1 (reasoning model) for ALL decisions
  - Never executes tools directly — delegates exclusively to specialists

Architecture rule: this is the ONLY agent that uses llm_role="reasoning".
"""
from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ── Path bootstrap ────────────────────────────────────────────────────────────
_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory

console = Console()


class OrchestratorAgent(BaseAgent):
    """
    Mission commander. Uses DeepSeek-R1 (reasoning model) for every decision.
    Delegates work to specialist agents and reacts to their findings.
    """

    # Ordered attack chain — phases run in this sequence
    ATTACK_CHAIN = [
        "recon",
        "enumeration",
        "vuln_scan",
        "exploitation",
        "privesc",
        "postexploit",
        "reporting",
    ]

    # Static phase gates: (description, result_field_to_check, minimum_value)
    PHASE_GATES: dict[str, tuple] = {
        "enumeration":  ("recon found live hosts",       "hosts_found",       1),
        "vuln_scan":    ("enum found open services",     "services_found",    1),
        "exploitation": ("vulnscan found exploitable",   "exploitable_vulns", 1),
        "privesc":      ("exploitation got a shell",     "shells_obtained",   1),
        "postexploit":  ("privesc got elevated access",  "root_obtained",     True),
        "reporting":    ("always runs",                  None,                None),
    }

    # Map ATTACK_CHAIN phase names → MissionMemory.update_phase() values
    _PHASE_MAP = {
        "recon":       "recon",
        "enumeration": "enum",
        "vuln_scan":   "vuln",
        "exploitation":"exploit",
        "privesc":     "privesc",
        "postexploit": "postexploit",
        "reporting":   "report",
    }

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="OrchestratorAgent",
            mission_memory=mission_memory,
            llm_role="reasoning",   # DeepSeek-R1:8b
            max_react_iterations=5,
        )
        self.phase_results: dict[str, dict] = {}
        self.current_phase: Optional[str] = None

    def _direct_llm(self, prompt: str) -> str:
        """
        Single-shot LLM call for internal orchestrator decisions.

        Uses the BASE deepseek-r1 model via ollama.Client directly (bypassing
        the custom Modelfile SYSTEM prompt which is ~4500 tokens and would make
        every short call take 3-4 extra minutes on CPU-only hardware).
        /no_think suppresses the chain-of-thought block; num_predict caps output.
        """
        try:
            import ollama as _ollama
            _cfg = self._load_base_model_name()
            client = _ollama.Client(host="http://localhost:11434")
            resp = client.chat(
                model=_cfg,
                messages=[
                    {"role": "system", "content": "You are a JSON-only pentest decision engine. Return valid JSON only."},
                    {"role": "user",   "content": "/no_think\n\n" + prompt},
                ],
                options={"num_predict": 128, "temperature": 0.05},
            )
            raw = resp["message"]["content"]
        except Exception as e:
            self.log_error(f"Direct LLM call failed: {e}")
            return ""
        return re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

    @staticmethod
    def _load_base_model_name() -> str:
        """Read the reasoning BASE model name from config (no Modelfile overhead)."""
        try:
            import yaml
            cfg_path = Path(__file__).parent.parent.parent / "config" / "models.yaml"
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            return cfg["models"]["reasoning_base"]["name"]   # deepseek-r1:8b-llama-distill-q4_K_M
        except Exception:
            return "deepseek-r1:8b-llama-distill-q4_K_M"

    def _extract_json(self, text: str) -> dict:
        """Extract the first JSON object from raw LLM text. Returns {} on failure."""
        json_m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", text, re.DOTALL)
        if json_m:
            try:
                return json.loads(json_m.group())
            except json.JSONDecodeError:
                pass
        # Try code block
        block_m = re.search(r"```(?:json)?\s*(\{.+?\})\s*```", text, re.DOTALL)
        if block_m:
            try:
                return json.loads(block_m.group(1))
            except json.JSONDecodeError:
                pass
        return {}

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, target: str, phase: str = "full") -> dict:
        """
        Execute the pentest mission against *target*.

        Args:
            target: IP address or domain name.
            phase:  "full" runs the entire chain; a phase name runs just that
                    phase plus "reporting".
        Returns:
            Mission summary dict.
        """
        # ── STEP 1: Mission banner ────────────────────────────────────────────
        self.console.print(Panel.fit(
            f"[bold white]🎯  Target :[/] [cyan]{target}[/]\n"
            f"[bold white]   Mission:[/] [cyan]{self.memory.mission_id}[/]\n"
            f"[bold white]   Models :[/] cyberagent-pentest:14b + cyberagent-reasoning:8b\n"
            f"[bold white]   RAG    :[/] 147,029 docs | Tools: 4,309+\n"
            f"[bold white]   Phase  :[/] [yellow]{phase}[/]",
            title="[bold red]CyberAgent PentestAI[/]",
            border_style="red",
        ))

        self.memory.log_action("Orchestrator", "mission_start", f"target={target} phase={phase}")

        # ── STEP 2: Initial planning ──────────────────────────────────────────
        prompt = (
            "/no_think\n\n"
            f"Target: {target}, Phase: {phase}.\n"
            'Return JSON: {"target_type":"ip","initial_hypothesis":"string",'
            '"recon_priorities":["ports","services"],'
            '"estimated_complexity":"medium","notes":"string"}'
        )
        raw = self._direct_llm(prompt)
        planning_result = self._extract_json(raw) or {"target_type": "ip", "notes": raw[:200]}
        self.memory.log_action("Orchestrator", "initial_planning", str(planning_result))

        # ── STEP 3: Execute attack chain ──────────────────────────────────────
        phases_to_run = self._get_phases_to_run(phase)

        for phase_name in phases_to_run:
            self.current_phase = phase_name

            self.console.print(Panel(
                f"[bold cyan]▶  PHASE: {phase_name.upper()}[/]",
                border_style="blue",
            ))

            # Phase gate check
            gate_passed, gate_reason = self._check_phase_gate(phase_name)
            if not gate_passed:
                self.log_warning(f"Phase '{phase_name}' skipped — gate not met: {gate_reason}")
                self.memory.log_action("Orchestrator", f"skip_{phase_name}", gate_reason)
                continue

            # Build agent briefing
            briefing = self._build_agent_briefing(phase_name)

            # Update mission memory phase
            mm_phase = self._PHASE_MAP.get(phase_name, phase_name)
            try:
                self.memory.update_phase(mm_phase)
            except ValueError as e:
                self.log_warning(f"update_phase({mm_phase}) skipped: {e}")

            # Instantiate and run specialist agent
            agent = self._get_agent(phase_name)
            self.log_info(f"Delegating to {agent.agent_name} for phase '{phase_name}'...")

            try:
                result = agent.run(target=target, briefing=briefing)
                self.phase_results[phase_name] = result
            except Exception as e:
                self.log_error(f"Agent '{phase_name}' crashed: {e}")
                result = {"success": False, "error": str(e)}
                self.phase_results[phase_name] = result

            # Post-phase analysis
            analysis = self._analyze_phase_result(phase_name, result)

            # Phase completion panel
            findings_count = analysis.get("findings_count", 0)
            recommended_next = analysis.get("recommended_next", "continue")
            key_insight = analysis.get("key_insight", "no insight")
            self.console.print(Panel(
                f"[green]✅ Findings: {findings_count}[/]\n"
                f"[white]Next: {recommended_next}[/]\n"
                f"[white]Insight: {key_insight}[/]",
                title=f"[green]PHASE {phase_name.upper()} COMPLETE[/]",
                border_style="green",
            ))

            # Strategy update on critical finding
            if analysis.get("critical_finding"):
                self._update_attack_strategy(analysis)

        # ── STEP 4: Mission summary ───────────────────────────────────────────
        return self._print_summary(target)

    # ── Phase helpers ─────────────────────────────────────────────────────────

    def _get_phases_to_run(self, phase: str) -> list[str]:
        """Determine which phases to execute based on the requested scope."""
        if phase == "full":
            return list(self.ATTACK_CHAIN)
        if phase in self.ATTACK_CHAIN:
            idx = self.ATTACK_CHAIN.index(phase)
            # Run the requested phase + all subsequent ones
            return self.ATTACK_CHAIN[idx:]
        # Single-phase shorthand
        return [phase] if phase in self.ATTACK_CHAIN else list(self.ATTACK_CHAIN)

    def _check_phase_gate(self, phase: str) -> tuple[bool, str]:
        """
        Determine whether conditions are met to run *phase*.
        1. Static check against PHASE_GATES + phase_results
        2. Quick LLM confirmation (single call, not full react loop)
        """
        if phase not in self.PHASE_GATES:
            return True, "No gate defined for this phase"

        condition_desc, required_field, min_val = self.PHASE_GATES[phase]

        # Reporting always runs
        if required_field is None:
            return True, condition_desc

        # ── Static check: look at results from previous phases ────────────────
        for _pname, result in self.phase_results.items():
            inner = result.get("result", {})
            if required_field in inner:
                actual = inner[required_field]
                if isinstance(min_val, bool):
                    if bool(actual) == min_val:
                        return True, f"Static gate passed: {required_field}={actual}"
                else:
                    if isinstance(actual, (int, float)) and actual >= min_val:
                        return True, f"Static gate passed: {required_field}={actual}"

        # ── Static check: look at MissionMemory state ─────────────────────────
        hosts = self.memory._state.get("hosts", {})
        if required_field == "hosts_found" and len(hosts) >= min_val:
            return True, f"State gate passed: {len(hosts)} hosts"
        if required_field == "services_found":
            total = sum(len(h.get("ports", [])) for h in hosts.values())
            if total >= min_val:
                return True, f"State gate passed: {total} services"
        if required_field == "exploitable_vulns":
            count = sum(
                sum(1 for v in h.get("vulnerabilities", []) if v.get("exploitable"))
                for h in hosts.values()
            )
            if count >= min_val:
                return True, f"State gate passed: {count} exploitable vulns"
        if required_field == "shells_obtained":
            shells = sum(len(h.get("shells", [])) for h in hosts.values())
            if shells >= min_val:
                return True, f"State gate passed: {shells} shells"
        if required_field == "root_obtained":
            root = any(
                any(p.get("root") for p in h.get("privesc_paths", []))
                for h in hosts.values()
            )
            if root == min_val:
                return True, "State gate passed: root obtained"

        # ── LLM dynamic check — only if static failed ─────────────────────────
        # Skip for stub runs where phase_results already have the required fields
        if self.phase_results:  # only call LLM if we have real previous results
            try:
                prompt = (
                    "/no_think\n\n"
                    f"Should we proceed with '{phase}'? Gate: {condition_desc}. "
                    f"Hosts: {len(hosts)}. "
                    f'Respond JSON: {{"proceed": true, "reason": "string"}}'
                )
                raw = self._direct_llm(prompt)
                data = self._extract_json(raw)
                if data:
                    return bool(data.get("proceed", False)), data.get("reason", "LLM decision")
            except Exception as e:
                self.log_warning(f"LLM gate check failed ({e}) — using static result")

        return False, f"Gate not met: {condition_desc}"

    def _build_agent_briefing(self, phase_name: str) -> dict:
        """
        Ask DeepSeek-R1 to compose a targeted briefing for the next specialist.
        Uses a short prompt to avoid context overflow.
        """
        hosts_summary = {ip: {"ports": len(h.get("ports", [])), "vulns": len(h.get("vulnerabilities", []))}
                         for ip, h in self.memory._state.get("hosts", {}).items()}
        prev_results = {k: v.get("result", {}) for k, v in list(self.phase_results.items())[-2:]}

        prompt = (
            "/no_think\n\n"
            f"Briefing for pentest agent '{phase_name}' against {self.memory.target}.\n"
            f"Known: {json.dumps(hosts_summary)}\n"
            f"Recent: {json.dumps(prev_results)}\n"
            'Return JSON: {"priority_targets":[],"known_info":{},"attack_vectors":[],'
            '"avoid":[],"rag_queries":["q1"],"special_instructions":"string"}'
        )
        raw = self._direct_llm(prompt)
        return self._extract_json(raw) or {"special_instructions": f"Focus on {phase_name} for {self.memory.target}"}

    def _analyze_phase_result(self, phase: str, result: dict) -> dict:
        """
        Ask DeepSeek-R1 to analyse what a specialist agent returned.
        Uses a short prompt to avoid context overflow.
        """
        inner = result.get("result", {})
        prompt = (
            "/no_think\n\n"
            f"Phase '{phase}' done. Success: {result.get('success')}. "
            f"Results: {json.dumps(inner)[:300]}\n"
            'Return JSON: {"success":true,"findings_count":0,"key_insight":"string",'
            '"critical_finding":false,"recommended_next":"string",'
            '"strategy_update":null,"attack_chain_adjustment":null}'
        )
        raw = self._direct_llm(prompt)
        return self._extract_json(raw) or {
            "success": bool(result.get("success")),
            "findings_count": len(inner) if isinstance(inner, dict) else 0,
            "key_insight": f"Phase {phase} {'succeeded' if result.get('success') else 'failed'}",
            "critical_finding": False,
            "recommended_next": "continue",
        }

    def _update_attack_strategy(self, analysis: dict):
        """Log a strategy pivot triggered by a critical finding."""
        reason = analysis.get("strategy_update") or analysis.get("key_insight", "critical finding")
        self.console.print(Panel(
            f"[bold yellow]🔄 STRATEGY UPDATE[/]\n[white]{reason}[/]",
            border_style="yellow",
        ))
        self.memory.log_action("Orchestrator", "strategy_update", reason)

    def _get_agent(self, phase_name: str) -> "BaseAgent":
        """
        Lazily import and instantiate the specialist agent for *phase_name*.
        This avoids circular imports at module load time.
        Raises ImportError if the module does not exist (should never happen
        once all specialists are implemented).
        """
        mapping = {
            "recon":       ("agents.recon_agent",       "ReconAgent"),
            "enumeration": ("agents.enumeration_agent", "EnumerationAgent"),
            "vuln_scan":   ("agents.vuln_scan_agent",   "VulnScanAgent"),
            "exploitation":("agents.exploitation_agent","ExploitationAgent"),
            "privesc":     ("agents.privesc_agent",     "PrivEscAgent"),
            "postexploit": ("agents.postexploit_agent", "PostExploitAgent"),
            "reporting":   ("agents.reporting_agent",   "ReportingAgent"),
        }

        if phase_name not in mapping:
            raise ValueError(f"Unknown phase: {phase_name}")

        module_path, class_name = mapping[phase_name]
        try:
            module = importlib.import_module(module_path)
        except ModuleNotFoundError:
            # Fallback: try src-prefixed path
            module = importlib.import_module(f"src.{module_path}")

        cls = getattr(module, class_name)
        return cls(mission_memory=self.memory)

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self, target: str) -> dict:
        """Print the mission summary table and return the final result dict."""
        table = Table(title="[bold]Mission Summary[/]", border_style="cyan")
        table.add_column("Phase", style="bold white")
        table.add_column("Result", style="cyan")

        root_obtained = False
        report_path = None

        for phase_name in self.ATTACK_CHAIN:
            result = self.phase_results.get(phase_name)
            if result is None:
                table.add_row(phase_name.title(), "[dim]skipped[/]")
                continue

            inner = result.get("result", {})
            success = result.get("success", False)
            stub = result.get("stub", False)

            if phase_name == "recon":
                detail = f"{inner.get('hosts_found', '?')} hosts"
            elif phase_name == "enumeration":
                detail = f"{inner.get('services_found', '?')} services"
            elif phase_name == "vuln_scan":
                detail = f"{inner.get('exploitable_vulns', '?')} exploitable vulns"
            elif phase_name == "exploitation":
                shells = inner.get("shells_obtained", 0)
                detail = f"{shells} shell(s)"
            elif phase_name == "privesc":
                root = inner.get("root_obtained", False)
                root_obtained = bool(root)
                detail = f"root={'Yes' if root else 'No'}"
            elif phase_name == "postexploit":
                detail = f"{inner.get('loot_count', '?')} loot items"
            elif phase_name == "reporting":
                report_path = inner.get("report_path")
                detail = f"saved to {report_path}" if report_path else "complete"
            else:
                detail = "complete" if success else "failed"

            if stub:
                detail += " [dim](stub)[/]"
            color = "green" if success else "red"
            table.add_row(phase_name.title(), f"[{color}]{detail}[/]")

        self.console.print(table)

        return {
            "mission_id": self.memory.mission_id,
            "target": target,
            "phases_completed": list(self.phase_results.keys()),
            "root_obtained": root_obtained,
            "report_path": report_path,
            "phase_results": self.phase_results,
        }
