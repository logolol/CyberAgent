"""
BaseAgent — parent class for ALL CyberAgent specialist agents.

Implements:
  - ReAct loop  (Thought → Action → Observation × N, then FINAL_ANSWER)
  - RAG context injection on every LLM call via ChromaManager
  - MissionMemory read/write
  - DynamicToolManager access (never subprocess directly)
  - Structured output validation via output_schemas.py
  - Rich terminal logging (no plain print() anywhere)

Architecture rule: every specialist agent inherits BaseAgent and overrides run().
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

# ── Path bootstrap ────────────────────────────────────────────────────────────
# Add src/ to sys.path so sibling packages (memory, utils, mcp, prompts) resolve
# whether this module is loaded as `src.agents.base_agent` or `agents.base_agent`.
_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from memory.mission_memory import MissionMemory
from memory.chroma_manager import ChromaManager
from utils.llm_factory import get_llm
from mcp.tool_manager import DynamicToolManager
from prompts.agent_prompts import get_agent_prompt, AGENT_PROMPTS

_log = logging.getLogger(__name__)


def is_verbose() -> bool:
    """Check if verbose mode is enabled via CA_VERBOSE env var."""
    return os.environ.get('CA_VERBOSE') == '1'


class BaseAgent:
    """
    Parent class for every CyberAgent specialist.

    Sub-classes must implement:
        run(self, target: str, briefing: dict = {}) -> dict
    """

    def __init__(
        self,
        agent_name: str,
        mission_memory: MissionMemory,
        llm_role: str = "default",
        max_react_iterations: int = 10,
    ):
        self.agent_name = agent_name
        self.llm = get_llm(role=llm_role)
        self.memory = mission_memory
        self.chroma = ChromaManager()
        self.tools = DynamicToolManager()
        self.console = Console()
        self.logger = logging.getLogger(f"agent.{agent_name}")
        self.max_iterations = max_react_iterations

    # ══════════════════════════════════════════════════════════════════════════
    # VERBOSE LOGGING HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _verbose(self, action: str, message: str) -> None:
        """Print verbose log line if CA_VERBOSE is set."""
        if is_verbose():
            self.console.print(
                f"[dim cyan][VERBOSE][{self.agent_name}][{action}][/] {message}"
            )

    def _verbose_tool_call(self, tool: str, args: list | str) -> None:
        """Log tool call before execution."""
        if is_verbose():
            args_str = ' '.join(str(a) for a in args) if isinstance(args, list) else str(args)
            self._verbose("TOOL_CALL", f"{tool} {args_str[:400]}")

    def _verbose_tool_output(self, output: str) -> None:
        """Log tool output after execution."""
        if is_verbose():
            self._verbose("TOOL_OUTPUT", output[:500].replace('\n', ' '))

    def _verbose_llm_prompt(self, prompt: str) -> None:
        """Log LLM prompt before call."""
        if is_verbose():
            self._verbose("LLM_PROMPT", prompt[:300].replace('\n', ' '))

    def _verbose_llm_response(self, response: str) -> None:
        """Log LLM response after call."""
        if is_verbose():
            self._verbose("LLM_RESPONSE", response[:300].replace('\n', ' '))

    def _verbose_llm_timeout(self, timeout_secs: int) -> None:
        """Log LLM timeout."""
        if is_verbose():
            self._verbose("LLM_TIMEOUT", f"timed out after {timeout_secs}s")

    def _verbose_attack_graph(self, nodes: list[dict]) -> None:
        """Log all attack graph nodes."""
        if is_verbose():
            self._verbose("ATTACK_GRAPH", f"{len(nodes)} nodes:")
            for n in nodes:
                self._verbose(
                    "ATTACK_GRAPH",
                    f"  {n.get('cve', 'CVE-UNKNOWN')} on {n.get('ip')}:{n.get('port')} "
                    f"state={n.get('state')} confidence={n.get('confidence', 0):.2f}"
                )

    def _verbose_shell_output(self, output: str) -> None:
        """Log shell command output."""
        if is_verbose():
            self._verbose("SHELL_OUTPUT", output[:500].replace('\n', ' | '))

    def _verbose_credential(self, username: str, password: str, service: str) -> None:
        """Log found credential."""
        if is_verbose():
            self._verbose("CREDENTIAL", f"{username}:{password} on {service}")

    def _verbose_phase_transition(self, from_phase: str, to_phase: str, intel: str) -> None:
        """Log phase transition with intelligence passed."""
        if is_verbose():
            self._verbose(
                "PHASE_TRANSITION",
                f"{from_phase} → {to_phase} | Intel: {intel[:200]}"
            )

    # ── Prompt helpers ────────────────────────────────────────────────────────

    def _format_rag(self, results: list[dict], max_per_hit: int = 250) -> str:
        """Convert ChromaDB result list into a prompt-injectable string."""
        if not results:
            return "No RAG results available."
        lines = []
        for r in results[:8]:
            src = r.get("source_collection", "unknown")
            text = r["text"][:max_per_hit].replace("\n", " ")
            lines.append(f"[{src}] {text}")
        return "\n---\n".join(lines)

    def _messages_to_prompt(self, messages: list[dict]) -> str:
        """
        Flatten a messages list (OpenAI format) into a single prompt string
        compatible with OllamaLLM (completion model, not chat model).
        """
        parts = []
        for msg in messages:
            role = msg["role"].upper()
            content = msg["content"]
            parts.append(f"<|{role}|>\n{content}")
        return "\n\n".join(parts) + "\n\n<|ASSISTANT|>\n"

    def _build_system_prompt(self, task: str) -> str:
        """Build the full system prompt with injected RAG and mission state."""
        rag_hits = self.chroma.get_rag_context(task[:300])
        rag_str = self._format_rag(rag_hits)

        # Resolve the AGENT_PROMPTS key: try as-is, then CamelCase→snake_case
        prompt_key = self.agent_name
        if prompt_key not in AGENT_PROMPTS:
            snake = re.sub(r"(?<!^)(?=[A-Z])", "_", self.agent_name).lower()
            prompt_key = snake if snake in AGENT_PROMPTS else None

        if prompt_key:
            return get_agent_prompt(
                agent_name=prompt_key,
                target=self.memory.target,
                mission_state=self.memory.get_full_context(),
                rag_context=rag_str,
            )
        # Graceful fallback for agents without a registered prompt
        return (
            f"You are {self.agent_name}, an expert penetration tester.\n"
            f"Target: {self.memory.target}\n\n"
            f"ANTI-HALLUCINATION: Only cite CVEs returned by RAG. Never invent findings.\n\n"
            f"RAG CONTEXT:\n{rag_str}"
        )

    # ── Response parser ───────────────────────────────────────────────────────

    def _parse_react_response(self, raw: str) -> dict:
        """
        Parse THOUGHT / ACTION / ACTION_INPUT / FINAL_ANSWER from raw LLM text.
        Returns dict with keys: thought, action, action_input, final_answer.
        """
        result: dict[str, Any] = {
            "thought": "",
            "action": None,
            "action_input": None,
            "final_answer": None,
        }

        # Strip DeepSeek-R1 <think>...</think> chain-of-thought wrapper
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

        # THOUGHT
        thought_m = re.search(
            r"THOUGHT:\s*(.+?)(?=ACTION:|FINAL_ANSWER:|$)", raw,
            re.DOTALL | re.IGNORECASE,
        )
        if thought_m:
            result["thought"] = thought_m.group(1).strip()

        # FINAL_ANSWER (JSON block) — check this first so we short-circuit
        final_m = re.search(
            r"FINAL_ANSWER:\s*(\{.+\})", raw, re.DOTALL | re.IGNORECASE
        )
        if final_m:
            try:
                result["final_answer"] = json.loads(final_m.group(1))
            except json.JSONDecodeError:
                result["final_answer"] = {"raw": final_m.group(1).strip()[:500]}
            return result

        # Try bare JSON block as FINAL_ANSWER (LLM sometimes skips the keyword)
        bare_json = re.search(r"```json\s*(\{.+?\})\s*```", raw, re.DOTALL)
        if bare_json:
            try:
                result["final_answer"] = json.loads(bare_json.group(1))
                result["thought"] = result["thought"] or "JSON block returned"
                return result
            except json.JSONDecodeError:
                pass

        # ACTION
        action_m = re.search(
            r"ACTION:\s*(\S+)", raw, re.IGNORECASE
        )
        if action_m:
            result["action"] = action_m.group(1).strip()

        # ACTION_INPUT
        input_m = re.search(
            r"ACTION_INPUT:\s*(\{.+?\})", raw, re.DOTALL | re.IGNORECASE
        )
        if input_m:
            try:
                result["action_input"] = json.loads(input_m.group(1))
            except json.JSONDecodeError:
                result["action_input"] = {"raw": input_m.group(1).strip()[:300]}

        return result

    # ── Command extraction and validation ─────────────────────────────────────

    def _extract_commands_from_output(self, llm_output: str) -> list[dict]:
        """
        Extract structured commands from LLM output for execution.
        Returns list of {tool: str, args: list, purpose: str, validation: dict}.

        This ensures all commands are validated before execution to prevent hallucination.
        """
        commands: list[dict] = []

        # Pattern 1: Structured ACTION blocks
        action_blocks = re.finditer(
            r"ACTION:\s*(\S+)\s*(?:ACTION_INPUT:\s*(\{[^}]+\}))?",
            llm_output,
            re.IGNORECASE | re.DOTALL
        )

        for match in action_blocks:
            tool = match.group(1).strip()
            action_input_str = match.group(2) if match.group(2) else "{}"

            try:
                action_input = json.loads(action_input_str)
            except json.JSONDecodeError:
                action_input = {"raw": action_input_str}

            # Validate command structure
            validation = self._validate_command_structure(tool, action_input)

            commands.append({
                "tool": tool,
                "args": action_input.get("args", []),
                "purpose": action_input.get("purpose", "Agent task"),
                "validation": validation,
                "raw_input": action_input
            })

        # Pattern 2: Inline tool mentions with arguments (e.g., "run nmap -sV 10.0.0.1")
        inline_commands = re.finditer(
            r"(?:run|execute|use)\s+(\w+)\s+([^\n]+)",
            llm_output,
            re.IGNORECASE
        )

        for match in inline_commands:
            tool = match.group(1).strip()
            args_str = match.group(2).strip()
            args = args_str.split()

            validation = self._validate_command_structure(tool, {"args": args})

            commands.append({
                "tool": tool,
                "args": args,
                "purpose": f"Inline {tool} command",
                "validation": validation,
                "raw_input": {"args": args}
            })

        return commands

    def _validate_command_structure(self, tool: str, action_input: dict) -> dict:
        """
        Validate a command before execution.
        Returns {valid: bool, issues: list[str], suggestions: list[str]}.
        """
        issues: list[str] = []
        suggestions: list[str] = []

        # Check 1: Tool exists
        try:
            # Try to get tool info from RAG
            tool_info = self.chroma.get_rag_context(f"{tool} usage examples", n=2)
            if not tool_info:
                issues.append(f"Tool '{tool}' not found in knowledge base")
                suggestions.append(f"Verify tool name or check if it's installed")
        except Exception:
            pass

        # Check 2: Required arguments
        args = action_input.get("args", [])
        if not args or len(args) == 0:
            # Some tools require arguments
            if tool.lower() in ["nmap", "hydra", "sqlmap", "gobuster", "nikto"]:
                issues.append(f"Tool '{tool}' typically requires arguments")
                suggestions.append(f"Check {tool} --help for required parameters")

        # Check 3: Argument format validation
        if isinstance(args, list):
            for arg in args:
                arg_str = str(arg)
                # Check for potentially dangerous patterns
                if any(pattern in arg_str for pattern in ["rm -rf", "dd if=", "> /dev/", "mkfs"]):
                    issues.append(f"Potentially destructive argument detected: {arg_str[:30]}")
                    suggestions.append("Use read-only reconnaissance commands only")

                # Check for incomplete arguments (flags without values)
                if arg_str.startswith("-") and arg_str in ["-o", "-p", "-t", "-u", "-w", "-f"]:
                    # These flags typically need a value
                    idx = args.index(arg)
                    if idx == len(args) - 1 or str(args[idx + 1]).startswith("-"):
                        issues.append(f"Flag '{arg_str}' appears to be missing its value")
                        suggestions.append(f"Provide value for {arg_str} flag")

        # Check 4: Cross-reference with tool's expected syntax from RAG
        if tool.lower() in ["nmap", "hydra", "sqlmap", "gobuster"]:
            try:
                rag_results = self.chroma.get_rag_context(f"{tool} command syntax examples", n=3)
                # Could add more sophisticated syntax checking here
            except Exception:
                pass

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "suggestions": suggestions,
            "tool": tool,
            "confidence": 1.0 if len(issues) == 0 else max(0.0, 1.0 - (len(issues) * 0.3))
        }

    # ── Action executor ───────────────────────────────────────────────────────

    def _execute_action(self, action: str, action_input: dict) -> Any:
        """
        Dispatch a parsed ACTION to the correct handler.
        Never raises — always returns a dict.
        """
        action = action.strip().lower()

        if action == "search_rag":
            query = action_input.get("query", "")
            results = self.chroma.get_rag_context(query)
            return {"results": [r["text"][:300] for r in results[:5]]}

        if action == "read_memory":
            phase = action_input.get("phase", "recon")
            return {"memory": self.memory.get_phase_summary(phase)}

        if action == "store_finding":
            try:
                self.memory.add_finding_from_dict(action_input)
                return {"stored": True}
            except Exception as e:
                return {"stored": False, "error": str(e)}

        # Default: try DynamicToolManager
        tool_args = action_input.get("args", [])
        if not isinstance(tool_args, list):
            tool_args = [str(tool_args)]
        purpose = action_input.get("purpose", f"{self.agent_name} task")
        try:
            return self.tools.use(action, args=tool_args, purpose=purpose)
        except Exception as e:
            return {"error": str(e), "tool": action}

    # ── Core ReAct loop ───────────────────────────────────────────────────────

    def react(self, task: str, context: dict = {}) -> dict:
        """
        ReAct loop: Thought → Action → Observation, up to max_iterations.

        Returns:
            {
              "agent": str,
              "success": bool,
              "result": dict,        # content of FINAL_ANSWER
              "iterations": int,
              "actions_taken": list,
              "error": str | None,
            }
        """
        system_prompt = self._build_system_prompt(task)
        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task},
        ]
        actions_taken: list[str] = []
        reformat_attempts = 0

        for i in range(self.max_iterations):
            prompt = self._messages_to_prompt(messages)

            # ── LLM call ────────────────────────────────────────────────
            try:
                raw = self.llm.invoke(prompt)
            except Exception as e:
                self.log_error(f"LLM call failed on iteration {i}: {e}")
                return self._fail_result(actions_taken, i, str(e))

            # ── Parse ────────────────────────────────────────────────────
            parsed = self._parse_react_response(raw)

            # Print thought
            if parsed["thought"]:
                self.console.print(Panel(
                    f"[white]{parsed['thought'][:400]}[/]",
                    title=f"[cyan]🤔 {self.agent_name} THOUGHT (iter {i+1})[/]",
                    border_style="cyan",
                ))

            # ── FINAL_ANSWER ─────────────────────────────────────────────
            if parsed["final_answer"] is not None:
                self.log_success(f"Done after {i+1} iteration(s)")
                # Run hallucination guard before returning
                phase = getattr(self, "current_phase", "unknown")
                guarded = self.hallucination_guard(parsed["final_answer"], phase)
                return {
                    "agent": self.agent_name,
                    "success": True,
                    "result": guarded,
                    "iterations": i + 1,
                    "actions_taken": actions_taken,
                    "error": None,
                }

            # ── No action parsed — ask LLM to reformat ───────────────────
            if not parsed["action"]:
                reformat_attempts += 1
                if reformat_attempts >= 2:
                    self.log_warning("LLM did not produce valid ReAct format after 2 attempts")
                    return self._fail_result(actions_taken, i, "invalid_react_format")
                messages.append({
                    "role": "user",
                    "content": (
                        "Please respond using exactly this format:\n"
                        "THOUGHT: <your reasoning>\n"
                        "ACTION: <tool_name>\n"
                        "ACTION_INPUT: {\"key\": \"value\"}\n\n"
                        "Or if finished:\n"
                        "THOUGHT: <reasoning>\n"
                        "FINAL_ANSWER: {<json result>}"
                    ),
                })
                continue

            # ── Execute action with validation ───────────────────────────
            action_input = parsed["action_input"] or {}

            # Validate command before execution
            validation = self._validate_command_structure(parsed["action"], action_input)

            if not validation["valid"]:
                self.console.print(Panel(
                    f"[red]⚠ Command validation failed:[/]\n"
                    f"[yellow]Issues:[/] {', '.join(validation['issues'])}\n"
                    f"[yellow]Suggestions:[/] {', '.join(validation['suggestions'])}",
                    title="[red]❌ VALIDATION FAILED[/]",
                    border_style="red",
                ))

                # Ask LLM to fix the command
                messages.append({
                    "role": "user",
                    "content": (
                        f"VALIDATION ERROR: The command you proposed has issues:\n"
                        f"Issues: {', '.join(validation['issues'])}\n"
                        f"Suggestions: {', '.join(validation['suggestions'])}\n\n"
                        f"Please revise your command and try again, or choose a different approach."
                    ),
                })
                continue

            self.console.print(Panel(
                f"[yellow]Tool:[/] {parsed['action']}\n"
                f"[yellow]Input:[/] {str(action_input)[:300]}\n"
                f"[green]Validation:[/] ✓ Passed (confidence: {validation['confidence']:.2f})",
                title="[yellow]⚡ ACTION[/]",
                border_style="yellow",
            ))

            # Execute with retry logic for transient failures
            result = None
            max_retries = 3
            for retry in range(max_retries):
                try:
                    result = self._execute_action(parsed["action"], action_input)

                    # Check if result indicates a transient error
                    if isinstance(result, dict) and "error" in result:
                        error_msg = str(result["error"]).lower()
                        transient_errors = ["timeout", "connection refused", "temporary failure", "try again"]

                        if any(err in error_msg for err in transient_errors) and retry < max_retries - 1:
                            self.log_warning(f"Transient error detected, retry {retry + 1}/{max_retries}")
                            import time
                            time.sleep(2 ** retry)  # Exponential backoff
                            continue

                    # Success or non-retriable error
                    break

                except Exception as e:
                    if retry < max_retries - 1:
                        self.log_warning(f"Execution failed, retry {retry + 1}/{max_retries}: {e}")
                        import time
                        time.sleep(2 ** retry)
                    else:
                        result = {"error": str(e), "tool": parsed["action"], "retries_exhausted": True}

            actions_taken.append(parsed["action"])

            self.console.print(Panel(
                f"[green]{str(result)[:300]}[/]",
                title="[green]👁 OBSERVATION[/]",
                border_style="green",
            ))

            # Log and store observation
            observation = {
                "iteration": i,
                "action": parsed["action"],
                "input": action_input,
                "output": str(result)[:500],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.memory.log_action(
                agent_name=self.agent_name,
                action=parsed["action"],
                result=str(result)[:500],
            )
            messages.append({
                "role": "user",
                "content": f"OBSERVATION: {json.dumps(observation)}",
            })

        # Max iterations reached
        self.log_warning(f"Max iterations ({self.max_iterations}) reached without FINAL_ANSWER")
        return self._fail_result(actions_taken, self.max_iterations, "max_iterations_reached")

    def _fail_result(self, actions_taken: list, iterations: int, error: str) -> dict:
        return {
            "agent": self.agent_name,
            "success": False,
            "result": {},
            "iterations": iterations,
            "actions_taken": actions_taken,
            "error": error,
        }

    # ── Hallucination guard ───────────────────────────────────────────────────

    def hallucination_guard(self, agent_output: dict, phase: str) -> dict:
        """
        Validate agent output before it reaches MissionMemory.
        Catches 10 classes of hallucination with multi-source validation. Never raises — always returns dict.

        Checks:
          1. CVE format — must match CVE-YYYY-NNNNN (year 1999-2026, id 4-7 digits)
          2. CVSS score — must be float 0.0–10.0
          3. Confirmed without evidence — demote to "potential" (evidence must be >20 chars)
          4. Vague version string — must look like a real version, not a description
          5. IP address format — must be valid IPv4 dotted-quad
          6. CVE existence — cross-reference with RAG CVE database + NVD API fallback
          7. Exploit path validation — verify exploit exists in ExploitDB or Metasploit
          8. Command syntax validation — check for common syntax errors in tool commands
          9. Port range validation — must be 1-65535
         10. Confidence score validation — must be 0.0-1.0

        Adds _hallucination_flags, _guard_passed, _validation_sources, _rejection_count to output.
        """
        import copy
        import ipaddress
        import urllib.request
        import ssl

        flags: list[str] = []
        validation_sources: list[str] = []
        rejection_count = 0
        cleaned = copy.deepcopy(agent_output)
        
        # Cache for CVE lookups to avoid repeated API calls
        cve_cache: dict[str, bool] = {}

        def _validate_cve_nvd_api(cve_id: str) -> bool:
            """Fallback to NVD API for CVE verification."""
            try:
                # NVD API v2.0
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "CyberAgent/1.0"})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    data = json.loads(resp.read().decode())
                    if data.get("totalResults", 0) > 0:
                        validation_sources.append(f"nvd_api:{cve_id}")
                        return True
                return False
            except Exception:
                return False

        def _validate_cve_exists(cve_id: str) -> bool:
            """Cross-reference CVE with RAG database, fallback to NVD API."""
            if cve_id in ("CVE-UNKNOWN", "CVE-INVALID-REMOVED", "CVE-UNVERIFIED"):
                return False
            
            # Check cache first
            if cve_id in cve_cache:
                return cve_cache[cve_id]
            
            # Try RAG database first
            try:
                results = self.chroma.get_rag_context(cve_id, n=3)
                for r in results:
                    if cve_id.upper() in r.get("text", "").upper():
                        validation_sources.append(f"cve_database:{cve_id}")
                        cve_cache[cve_id] = True
                        return True
            except Exception:
                pass
            
            # Fallback to NVD API (rate-limited, so only for misses)
            if _validate_cve_nvd_api(cve_id):
                cve_cache[cve_id] = True
                return True
            
            flags.append(f"cve_not_verified:{cve_id}")
            cve_cache[cve_id] = False
            return False

        def _validate_exploit_path(exploit_path: str) -> bool:
            """Verify exploit exists in ExploitDB or is a valid Metasploit module path."""
            if not exploit_path or exploit_path.strip() == "":
                return True  # Empty is acceptable

            # Check EDB-ID format
            if re.match(r"^EDB-ID:\d+$", exploit_path, re.IGNORECASE):
                edb_id = exploit_path.split(":")[1]
                try:
                    results = self.chroma.get_rag_context(f"EDB-ID {edb_id}", n=3)
                    for r in results:
                        if edb_id in r.get("text", ""):
                            validation_sources.append(f"exploitdb:EDB-{edb_id}")
                            return True
                    flags.append(f"exploit_not_found:{exploit_path}")
                    return False
                except Exception:
                    return False

            # Check Metasploit module path format
            if "/" in exploit_path and not exploit_path.startswith("/"):
                # Valid format like "exploit/linux/http/apache_mod_cgi"
                validation_sources.append(f"metasploit_format:{exploit_path}")
                return True

            flags.append(f"invalid_exploit_path_format:{exploit_path}")
            return False

        def _validate_command_syntax(command: str, tool: str = "") -> bool:
            """Check for common command syntax errors and injection attempts."""
            if not command or not isinstance(command, str):
                return True

            # Check for unmatched quotes
            single_quotes = command.count("'") - command.count("\\'")
            double_quotes = command.count('"') - command.count('\\"')
            if single_quotes % 2 != 0 or double_quotes % 2 != 0:
                flags.append(f"unmatched_quotes_in_command:{command[:50]}")
                return False

            # Check for incomplete pipe/redirect
            if command.strip().endswith(("|", ">", "<", ">>", "&&", "||")):
                flags.append(f"incomplete_command:{command[:50]}")
                return False

            # Expanded injection detection patterns
            injection_patterns = [
                r";.*rm\s+-",        # ;rm -rf
                r";.*curl\s+",       # ;curl download
                r"\$\(.*rm\s",       # $(rm
                r"`.*rm\s",          # `rm
                r";\s*wget\s+",      # ;wget
                r";\s*chmod\s+",     # ;chmod
                r";\s*mkfs\s+",      # ;mkfs
                r";\s*dd\s+if=",     # ;dd
                r"\|\s*sh\b",        # | sh
                r"\|\s*bash\b",      # | bash
                r";\s*python.*-c",   # ;python -c
                r";\s*perl.*-e",     # ;perl -e
                r"base64\s+-d\s*\|", # base64 -d | (decode & exec)
            ]
            for pattern in injection_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    flags.append(f"injection_pattern_detected:{command[:50]}")
                    return False

            return True
        
        def _validate_evidence(evidence: str) -> bool:
            """Validate evidence is substantive, not just placeholder."""
            if not evidence or not isinstance(evidence, str):
                return False
            evidence = evidence.strip()
            # Must be at least 20 chars and not just generic phrases
            if len(evidence) < 20:
                return False
            generic_phrases = [
                "confirmed", "verified", "found", "detected", "true", 
                "yes", "present", "exists", "vulnerable", "exploitable"
            ]
            if evidence.lower() in generic_phrases:
                return False
            return True

        def _check_dict(obj: Any):
            nonlocal rejection_count
            if not isinstance(obj, dict):
                return
            for k, v in list(obj.items()):
                # CHECK 1 — CVE format
                if isinstance(v, str):
                    for cve in re.findall(r"CVE-[\w-]+", v, re.IGNORECASE):
                        if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve.upper()):
                            obj[k] = v.replace(cve, "CVE-INVALID-REMOVED")
                            flags.append(f"invalid_cve_format:{cve}")
                            rejection_count += 1
                elif k in ("cve",) and v is not None and isinstance(v, str):
                    if v not in ("CVE-UNKNOWN", "CVE-UNVERIFIED") and not re.match(r"^CVE-\d{4}-\d{4,7}$", v):
                        obj[k] = "CVE-INVALID-REMOVED"
                        flags.append(f"invalid_cve_format:{v}")
                        rejection_count += 1
                    # CHECK 6 — CVE existence validation with NVD fallback
                    elif v not in ("CVE-UNKNOWN", "CVE-INVALID-REMOVED", "CVE-UNVERIFIED"):
                        if not _validate_cve_exists(v):
                            obj[k] = "CVE-UNVERIFIED"
                            obj["requires_verification"] = True

                # CHECK 2 — CVSS range
                if k in ("cvss", "cvss_score", "score") and v is not None:
                    try:
                        score = float(v)
                        if not (0.0 <= score <= 10.0):
                            obj[k] = None
                            flags.append(f"invalid_cvss:{v}")
                            rejection_count += 1
                    except (TypeError, ValueError):
                        obj[k] = None
                        flags.append(f"invalid_cvss:{v}")
                        rejection_count += 1

                # CHECK 4 — version string sanity (≤4 words → likely real version)
                if k in ("version", "service_version", "ver") and isinstance(v, str) and v:
                    if len(v.split()) > 4:
                        obj[k] = "version_unknown"
                        flags.append(f"vague_version_string:{v[:50]}")

                # CHECK 5 — IP address
                if k in ("ip", "host", "target", "rhost") and isinstance(v, str) and v:
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
                        try:
                            ipaddress.ip_address(v)
                        except ValueError:
                            del obj[k]
                            flags.append(f"invalid_ip:{v}")
                            rejection_count += 1

                # CHECK 7 — Exploit path validation
                if k in ("exploit_path", "exploit_module", "module_path") and isinstance(v, str):
                    _validate_exploit_path(v)

                # CHECK 8 — Command syntax validation
                if k in ("command", "cmd", "tool_command") and isinstance(v, str):
                    _validate_command_syntax(v, obj.get("tool", ""))
                
                # CHECK 9 — Port range validation
                if k in ("port", "lport", "rport", "shell_port") and v is not None:
                    try:
                        port = int(v)
                        if not (1 <= port <= 65535):
                            obj[k] = None
                            flags.append(f"invalid_port:{v}")
                            rejection_count += 1
                    except (TypeError, ValueError):
                        pass
                
                # CHECK 10 — Confidence score validation
                if k in ("confidence", "conf", "score") and v is not None:
                    try:
                        conf = float(v)
                        if not (0.0 <= conf <= 1.0):
                            obj[k] = max(0.0, min(1.0, conf))  # Clamp to valid range
                            flags.append(f"confidence_clamped:{v}")
                    except (TypeError, ValueError):
                        pass

                # Recurse
                if isinstance(v, dict):
                    _check_dict(v)
                elif isinstance(v, list):
                    _check_list(v)

        def _check_list(lst: list):
            nonlocal rejection_count
            for item in lst:
                if isinstance(item, dict):
                    # CHECK 3 — confirmed without SUBSTANTIVE evidence
                    if item.get("confirmed") is True:
                        evidence = item.get("evidence", "")
                        if not _validate_evidence(evidence):
                            item["confirmed"] = False
                            item["potential"] = True
                            flags.append("unconfirmed_finding_demoted")
                            rejection_count += 1
                    _check_dict(item)
                elif isinstance(item, list):
                    _check_list(item)

        _check_dict(cleaned)

        # Also walk top-level list values
        for k, v in cleaned.items():
            if isinstance(v, list):
                _check_list(v)

        cleaned["_hallucination_flags"] = flags
        cleaned["_guard_passed"] = len(flags) == 0
        cleaned["_validation_sources"] = validation_sources
        cleaned["_rejection_count"] = rejection_count

        if flags:
            self.log_warning(f"Hallucination guard: {len(flags)} issue(s), {rejection_count} rejected — {flags[:5]}")
        if validation_sources:
            self.log_info(f"Validated against {len(validation_sources)} external source(s)")

        return cleaned

    # ── Logging helpers ───────────────────────────────────────────────────────

    def log_info(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[cyan]ℹ {self.agent_name}[/]",
            border_style="cyan",
        ))

    def log_success(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[green]✓ {self.agent_name}[/]",
            border_style="green",
        ))

    def log_warning(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[yellow]⚠ {self.agent_name}[/]",
            border_style="yellow",
        ))

    def log_error(self, msg: str):
        self.console.print(Panel(
            f"[white]{msg}[/]",
            title=f"[red]✗ {self.agent_name}[/]",
            border_style="red",
        ))

    def _llm_with_timeout(
        self, prompt: str, timeout: int = 300
    ) -> str:
        """
        Run self.llm.invoke(prompt) with a timeout.
        Returns raw response string or empty string on failure.
        Safe to call from any agent that inherits BaseAgent.
        
        Default timeout increased to 300s because:
        - Warm models take 20-40s for complex prompts with large context
        - Cold starts can take 60-120s (model loading from disk)
        - Better to complete slowly than fail with empty fallback
        
        Now includes model keep-alive ping to prevent cold starts.
        """
        import concurrent.futures
        import threading
        import weakref
        import concurrent.futures.thread
        import time

        # VERBOSE: Log prompt before LLM call
        self._verbose_llm_prompt(prompt)
        
        # Note: Model warmup is handled by llm_factory.warm_model() at startup
        # We skip ping here to avoid blocking - keep_alive="2h" in LLM config suffices

        class _DaemonExecutor(concurrent.futures.ThreadPoolExecutor):
            def _adjust_thread_count(self):
                if self._idle_semaphore.acquire(timeout=0):
                    return
                def wcb(_, q=self._work_queue):
                    q.put(None)
                n = len(self._threads)
                if n < self._max_workers:
                    t = threading.Thread(
                        target=concurrent.futures.thread._worker,
                        args=(weakref.ref(self, wcb),
                              self._work_queue,
                              self._initializer,
                              self._initargs),
                    )
                    t.daemon = True
                    t.start()
                    self._threads.add(t)
                    concurrent.futures.thread._threads_queues[t] = \
                        self._work_queue

        ex = _DaemonExecutor(max_workers=1)
        future = ex.submit(self.llm.invoke, prompt)
        try:
            response = future.result(timeout=timeout)
            result = (response.content
                    if hasattr(response, "content")
                    else str(response))
            # VERBOSE: Log response after LLM call
            self._verbose_llm_response(result)
            return result
        except concurrent.futures.TimeoutError:
            self.log_warning(
                f"LLM decision timed out after {timeout}s"
            )
            # VERBOSE: Log timeout
            self._verbose_llm_timeout(timeout)
            future.cancel()
            return ""
        except Exception as e:
            self.log_warning(f"LLM call failed: {e}")
            return ""
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    # ── Public helper methods (inherited by all specialists) ──────────────────

    def get_rag_for_task(self, task: str, n: int = 5) -> str:
        """Semantic RAG lookup, returns formatted string for prompt injection."""
        results = self.chroma.get_rag_context(task, n=n)
        return self._format_rag(results)

    def store_finding(self, finding_type: str, data: dict):
        """
        Store a finding in both MissionMemory and ChromaDB.
        finding_type: "host" | "port" | "vuln" | "shell" | "cred" | "loot"
        """
        data_with_type = {"finding_type": finding_type, **data}
        self.memory.add_finding_from_dict(data_with_type)
        self.memory.store_in_chroma(
            str(data),
            {"finding_type": finding_type, "agent": self.agent_name},
        )

    def run_tool(self, tool: str, context: dict) -> dict:
        """
        Execute a tool via DynamicToolManager.
        Logs result to MissionMemory. Never raises.
        """
        args = context.pop("args", [])
        if not isinstance(args, list):
            args = [str(args)]
        purpose = context.get("purpose", f"{self.agent_name}: {tool}")
        try:
            result = self.tools.use(tool, args=args, purpose=purpose)
            self.memory.log_action(self.agent_name, tool, str(result)[:300])
            return result if isinstance(result, dict) else {"output": str(result)}
        except Exception as e:
            self.log_error(f"Tool '{tool}' failed: {e}")
            return {"error": str(e), "tool": tool}
