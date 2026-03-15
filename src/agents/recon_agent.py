"""
ReconAgent — wave-based PASSIVE reconnaissance specialist.

Execution model:
  - Max 3 waves.
  - Wave 1 uses a fixed baseline tool set.
  - Wave 2/3 are selected by the LLM from the passive tool catalog.
  - Each wave runs tools in bounded parallel batches (max 3 workers).

Architecture:
  - Uses BaseAgent + DynamicToolManager (no direct subprocess in this agent).
  - Uses regex parsing for findings extraction (no LLM parsing of raw tool output).
  - Applies hallucination_guard() to extracted findings before persistence.
"""
from __future__ import annotations

import concurrent.futures
import concurrent.futures.thread
import ipaddress
import json
import psutil
import re
import shutil
import socket
import sys
import threading
import weakref
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.table import Table

_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class ReconAgent(BaseAgent):
    """Passive recon agent with wave-based, bounded-concurrency execution."""

    PASSIVE_TOOLS: dict[str, dict[str, Any]] = {
        "dns_resolve": {
            "tool": "dig",
            "args": ["{target}", "ANY", "+short"],
            "purpose": "Resolve target DNS records",
        },
        "dns_all_records": {
            "tool": "dig",
            "args": ["{target}", "A", "AAAA", "MX", "NS", "TXT", "SOA", "+short"],
            "purpose": "Collect key DNS record types",
        },
        "host_lookup": {
            "tool": "host",
            "args": ["-a", "{target}"],
            "purpose": "Expanded DNS host lookup",
        },
        "whois_domain": {
            "tool": "whois",
            "args": ["{target}"],
            "purpose": "Domain WHOIS lookup",
        },
        "whois_ip": {
            "tool": "whois",
            "args": ["{ip}"],
            "purpose": "IP WHOIS lookup",
            "requires_ip": True,
        },
        "reverse_dns": {
            "tool": "dig",
            "args": ["-x", "{ip}", "+short"],
            "purpose": "Reverse DNS lookup",
            "requires_ip": True,
        },
        "mx_lookup": {
            "tool": "dig",
            "args": ["{target}", "MX", "+short"],
            "purpose": "MX record lookup",
        },
        "ns_lookup": {
            "tool": "dig",
            "args": ["{target}", "NS", "+short"],
            "purpose": "NS record lookup",
        },
        "txt_lookup": {
            "tool": "dig",
            "args": ["{target}", "TXT", "+short"],
            "purpose": "TXT record lookup",
        },
        "spf_check": {
            "tool": "dig",
            "args": ["{target}", "TXT", "+short"],
            "purpose": "SPF TXT check",
        },
        "cert_transparency": {
            "tool": "curl",
            "args": ["-s", "--max-time", "15", "https://crt.sh/?q=%.{target}&output=json"],
            "purpose": "Certificate transparency search",
        },
        "subfinder_passive": {
            "tool": "subfinder",
            "args": ["-d", "{target}", "-silent", "-timeout", "30"],
            "purpose": "Passive subdomain discovery",
        },
        "theharvester_ddg": {
            "tool": "theHarvester",
            "args": ["-d", "{target}", "-l", "50", "-b", "duckduckgo"],
            "purpose": "OSINT email and host discovery",
        },
        "theharvester_bing": {
            "tool": "theHarvester",
            "args": ["-d", "{target}", "-l", "30", "-b", "bing"],
            "purpose": "Additional OSINT email and host discovery",
        },
        "whatweb_passive": {
            "tool": "whatweb",
            "args": ["--color=never", "--no-errors", "-a", "1", "http://{target}"],
            "purpose": "Passive web technology fingerprinting",
        },
        "wafw00f_check": {
            "tool": "wafw00f",
            "args": ["http://{target}", "-o", "-"],
            "purpose": "WAF fingerprinting",
        },
        "asn_lookup": {
            "tool": "whois",
            "args": ["-h", "whois.cymru.com", "-v", "{ip}"],
            "purpose": "ASN and network ownership lookup",
            "requires_ip": True,
        },
        "wayback_check": {
            "tool": "curl",
            "args": ["-s", "--max-time", "15", "http://archive.org/wayback/available?url={target}"],
            "purpose": "Wayback snapshot availability check",
        },
        "security_headers": {
            "tool": "curl",
            "args": ["-sI", "--max-time", "10", "http://{target}"],
            "purpose": "HTTP response header collection",
        },
        "robots_passive": {
            "tool": "curl",
            "args": ["-s", "--max-time", "10", "http://{target}/robots.txt"],
            "purpose": "robots.txt passive inspection",
        },
    }

    OPTIONAL_PASSIVE_TOOLS: dict[str, dict[str, Any]] = {
        "dnsx_resolve": {
            "tool": "dnsx",
            "args": ["-d", "{target}", "-silent"],
            "purpose": "Passive DNS resolution via dnsx",
        },
        "amass_passive": {
            "tool": "amass",
            "args": ["enum", "-passive", "-d", "{target}", "-timeout", "30"],
            "purpose": "Passive subdomain discovery via amass",
        },
        "whatweb_full": {
            "tool": "whatweb",
            "args": ["--color=never", "-a", "3", "http://{target}"],
            "purpose": "Deeper passive web technology fingerprinting",
        },
        "curl_headers": {
            "tool": "curl",
            "args": ["-sI", "--max-time", "10", "--follow", "http://{target}"],
            "purpose": "HTTP header collection with redirect following",
        },
        "ssl_check": {
            "tool": "curl",
            "args": ["-sI", "--max-time", "10", "https://{target}"],
            "purpose": "HTTPS header collection",
        },
    }

    WAVE_1_TOOLS = ["dns_resolve", "dns_all_records", "whois_domain", "cert_transparency", "security_headers"]
    MAX_WAVES = 3
    MAX_CONCURRENT = 5
    DEFAULT_TOOL_TIMEOUT = 30
    TOOL_TIMEOUTS: dict[str, int] = {
        "dns_resolve": 10,
        "dns_all_records": 10,
        "reverse_dns": 10,
        "mx_lookup": 10,
        "ns_lookup": 10,
        "txt_lookup": 10,
        "spf_check": 10,
        "security_headers": 10,
        "cert_transparency": 15,
        "wayback_check": 15,
        "robots_passive": 10,
        "ssl_check": 10,
        "whatweb_passive": 20,
        "whatweb_full": 25,
        "wafw00f_check": 20,
        "curl_headers": 10,
        "whois_domain": 20,
        "whois_ip": 15,
        "asn_lookup": 15,
        "subfinder_passive": 40,
        "theharvester_ddg": 60,
        "theharvester_bing": 60,
        "amass_passive": 60,
    }
    OUTPUT_TRUNCATE = 2000

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
    _DOMAIN_RE = re.compile(r"\b(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="ReconAgent",
            mission_memory=mission_memory,
            llm_role="default",
        )
        self.target = mission_memory.target
        self.target_type = "domain"
        self.resolved_ip: str | None = None
        self.all_raw_outputs: dict[str, str] = {}
        self.all_findings: dict[str, Any] = {}
        self.tool_specs: dict[str, dict[str, Any]] = {
            name: dict(spec) for name, spec in self.PASSIVE_TOOLS.items()
        }
        self.available_tools: dict[str, bool] = {}
        self._register_optional_tools()
        self._build_available_tools_registry()

    def run(self, target: str, briefing: dict = {}) -> dict:
        self._reset_state(target)

        self.console.print(Panel.fit(
            f"[bold]🔍 ReconAgent — Passive Reconnaissance[/]\n"
            f"Target: [cyan]{target}[/]\n"
            f"Model role: [cyan]default[/] | Waves: [cyan]max {self.MAX_WAVES}[/]\n"
            f"Concurrency: [cyan]{self.MAX_CONCURRENT} tools parallel[/]",
            title="[bold blue]Recon Phase[/]",
            border_style="blue",
        ))

        current_wave_tools = list(self.WAVE_1_TOOLS)
        waves_completed = 0

        for wave_num in range(1, self.MAX_WAVES + 1):
            if not current_wave_tools:
                self.log_info("No tools scheduled for this wave. Recon complete.")
                break

            self.console.print(Panel(
                f"[bold cyan]🌊 WAVE {wave_num}[/] — [white]{len(current_wave_tools)} tool(s)[/]",
                border_style="cyan",
            ))

            wave_results = self._run_wave(current_wave_tools, wave_num)
            self.all_raw_outputs.update(wave_results)
            self._extract_findings_from_wave(wave_results, wave_num)
            waves_completed = wave_num

            if wave_num == 1:
                dns_blob = "\n".join([
                    wave_results.get("dns_resolve", ""),
                    wave_results.get("dns_all_records", ""),
                    wave_results.get("host_lookup", ""),
                ])
                self.resolved_ip = self._extract_ip_from_dns(dns_blob)
                if self.resolved_ip:
                    self.log_success(f"Target resolved: {target} → {self.resolved_ip}")
                    existing = [h["ip"] for h in self.all_findings["hosts"]]
                    if self.resolved_ip not in existing:
                        self.all_findings["hosts"].append({
                            "hostname": self.target,
                            "ip": self.resolved_ip,
                            "source": "dns_resolution",
                        })
                    self.target_type = self._detect_target_type()

            if wave_num == self.MAX_WAVES:
                self.log_success(f"Recon complete after {wave_num} wave(s)")
                break

            next_tools, done = self._decide_next_wave(wave_num, wave_results)
            if done:
                self.log_success(f"Recon complete after {wave_num} wave(s)")
                break

            current_wave_tools = next_tools
            if not current_wave_tools:
                self.log_info("No additional useful passive tools suggested. Stopping.")
                break

        final_findings = self._compile_final_findings()
        self._write_to_memory(final_findings)
        self._print_summary(final_findings, waves_completed)

        return {
            "agent": self.agent_name,
            "success": True,
            "result": final_findings,
            "raw_outputs": self.all_raw_outputs,
            "waves_completed": waves_completed,
        }

    def _reset_state(self, target: str):
        self.target = target.strip()
        self.resolved_ip = None
        self.target_type = self._detect_target_type()
        self.all_raw_outputs = {}
        self.all_findings = {
            "hosts": [],          # {"hostname": str, "ip": str, "source": str}
            "subdomains": [],     # [str]
            "technologies": [],   # {"name": str, "version": str, "evidence": str, "source": str}
            "osint_intel": [],    # {"type": str, "value": str, "source": str}
            "network_info": {},   # {"org": str, "registrar": str, "country": str, "asn": str, "ip_range": str}
            "web_info": {"headers": {}},
        }

    def _register_optional_tools(self):
        for tool_name, spec in self.OPTIONAL_PASSIVE_TOOLS.items():
            if self._tool_binary_available(spec):
                self.tool_specs[tool_name] = dict(spec)

    def _build_available_tools_registry(self):
        self.available_tools = {}
        for tool_name, spec in self.tool_specs.items():
            available = self._tool_binary_available(spec)
            self.available_tools[tool_name] = available
            if not available:
                binary = spec.get("tool", "unknown")
                self.log_warning(f"Tool not available: {tool_name} ({binary}) — will skip")

    def _tool_binary_available(self, tool_spec: dict[str, Any]) -> bool:
        binary = str(tool_spec.get("tool", "")).strip()
        if not binary:
            return False

        if binary == "python3":
            args = tool_spec.get("args", [])
            script = str(args[0]) if args else ""
            if script.startswith("/") or script.startswith("~"):
                return Path(script).expanduser().exists()
            return True

        if binary in {"curl", "dig", "whois", "host"}:
            return True

        try:
            return self.tools.find(binary) is not None
        except Exception:
            return shutil.which(binary) is not None

    def _run_wave(self, tools: list[str], wave_num: int) -> dict[str, str]:
        """Run wave tools in batches of up to MAX_CONCURRENT workers."""
        del wave_num  # wave_num is for readability in caller logs
        results: dict[str, str] = {}
        cpu_load = psutil.cpu_percent(interval=0.1)
        workers = 2 if cpu_load > 80 else self.MAX_CONCURRENT
        workers = max(1, workers)

        for batch_start in range(0, len(tools), workers):
            batch = tools[batch_start: batch_start + workers]
            batch_timeout = max(
                self.TOOL_TIMEOUTS.get(tool_name, self.DEFAULT_TOOL_TIMEOUT)
                for tool_name in batch
            ) + 10

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._run_single_tool, tool_name): tool_name
                    for tool_name in batch
                }

                try:
                    for future in concurrent.futures.as_completed(futures, timeout=batch_timeout):
                        tool_name = futures[future]
                        try:
                            output = future.result(timeout=1)
                            results[tool_name] = output
                            preview = output[:100].replace("\n", " ") if output else "[no output]"
                            self.log_info(f"✓ {tool_name}: {preview}...")
                        except Exception as exc:
                            msg = f"[ERROR: {str(exc)[:120]}]"
                            results[tool_name] = msg
                            self.log_warning(f"✗ {tool_name}: {exc}")
                except concurrent.futures.TimeoutError:
                    for future, tool_name in futures.items():
                        if future.done():
                            continue
                        future.cancel()
                        tool_timeout = self.TOOL_TIMEOUTS.get(tool_name, self.DEFAULT_TOOL_TIMEOUT)
                        results[tool_name] = f"[TIMEOUT after {tool_timeout}s]"
                        self.log_warning(f"⏱ {tool_name}: timed out")

        return results

    def _run_single_tool(self, tool_name: str) -> str:
        """Execute one passive tool through DynamicToolManager and return capped output."""
        spec = self.tool_specs.get(tool_name)
        if not spec:
            return f"[UNKNOWN TOOL: {tool_name}]"

        if not self.available_tools.get(tool_name, False):
            return "[TOOL_NOT_AVAILABLE]"

        if spec.get("requires_ip") and not self.resolved_ip:
            self.log_warning(f"{tool_name} skipped: target IP not resolved yet")
            return "[SKIPPED: no resolved IP]"

        binary = spec["tool"]
        try:
            binary_found = self.tools.find(binary) is not None
        except Exception:
            binary_found = shutil.which(binary) is not None
        if not binary_found:
            self.log_warning(f"{tool_name} skipped: binary not found ({binary})")
            return f"[SKIPPED: tool not found: {binary}]"

        args = self._render_args(spec.get("args", []))
        timeout = self.TOOL_TIMEOUTS.get(tool_name, self.DEFAULT_TOOL_TIMEOUT)
        result = self.tools.use(
            binary,
            args=args,
            purpose=spec.get("purpose", "passive recon"),
            timeout=timeout,
        )

        output: str
        if not isinstance(result, dict):
            output = str(result)
        else:
            stdout = (result.get("stdout") or "").strip()
            stderr = (result.get("stderr") or "").strip()
            error = (result.get("error") or "").strip()
            output = stdout or stderr or error or "[no output]"
            if not result.get("success", False) and error:
                self.log_warning(f"{tool_name} failed: {error}")

        output = output[:self.OUTPUT_TRUNCATE]
        self.memory.log_action(self.agent_name, tool_name, output[:200])
        return output

    def _render_args(self, args_template: list[str]) -> list[str]:
        target = self.target
        ip_value = self.resolved_ip or self.target
        rendered = []
        for arg in args_template:
            rendered.append(
                str(arg)
                .replace("{target}", target)
                .replace("{ip}", ip_value)
            )
        return rendered

    def _decide_next_wave(self, wave_num: int, wave_results: dict[str, str]) -> tuple[list[str], bool]:
        """
        Let the LLM choose next passive tools from unused catalog.
        Returns (next_tools, done).
        """
        target_type = self._detect_target_type()
        if target_type == "internal":
            return self._heuristic_next_wave(wave_num)

        unused_tools = [
            tool_name for tool_name in self.tool_specs.keys()
            if tool_name not in self.all_raw_outputs and self.available_tools.get(tool_name, False)
        ]

        if not unused_tools:
            return [], True

        summary = self._summarize_wave_output(wave_results)
        rag_hits = self.chroma.get_rag_context(
            f"passive recon next steps for {self.target}",
            collections=["hacktricks", "mitre_attack", "owasp"],
            n=3,
        )
        rag_text = "\n".join(
            f"- [{h.get('source_collection', 'rag')}] {h.get('text', '')[:180]}"
            for h in rag_hits[:4]
        ) or "- No RAG context found."

        prompt = f"""You are selecting PASSIVE reconnaissance steps only.
Target: {self.target}
Resolved IP: {self.resolved_ip or "not resolved"}
Current wave: {wave_num}

Wave results summary:
{summary}

Current findings:
- hosts: {len(self.all_findings["hosts"])}
- subdomains: {len(self.all_findings["subdomains"])}
- technologies: {len(self.all_findings["technologies"])}
- osint items: {len(self.all_findings["osint_intel"])}

RAG hints:
{rag_text}

Available unused tools:
{json.dumps(unused_tools)}

Rules:
- PASSIVE reconnaissance only.
- Choose at most 3 tools.
- Only choose tools likely to reveal NEW data.
- If recon is sufficient, set done=true.

Return JSON ONLY:
{{
  "done": false,
  "reasoning": "brief reason",
  "next_tools": ["tool_a", "tool_b"],
  "priority_finding": "short sentence"
}}
"""
        try:
            raw = self._llm_with_timeout(prompt, timeout=90)
            if not raw:
                fallback = self._fallback_next_tools(wave_num)
                return fallback, len(fallback) == 0
            raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
            data = self._extract_json_dict(raw)

            if data:
                done = bool(data.get("done", False))
                suggested = data.get("next_tools", [])
                if not isinstance(suggested, list):
                    suggested = []

                filtered = []
                for tool_name in suggested:
                    if tool_name not in self.tool_specs:
                        continue
                    if tool_name in self.all_raw_outputs:
                        continue
                    if not self.available_tools.get(tool_name, False):
                        continue
                    if self.tool_specs[tool_name].get("requires_ip") and not self.resolved_ip:
                        continue
                    filtered.append(tool_name)
                filtered = filtered[:self.MAX_CONCURRENT]

                key_finding = str(data.get("priority_finding", "")).strip()
                if key_finding:
                    self.log_info(f"🔍 Key finding: {key_finding}")

                if done and not filtered:
                    return [], True
                if filtered:
                    return filtered, False
        except Exception as exc:
            self.log_warning(f"LLM wave decision failed: {exc}")

        fallback = self._fallback_next_tools(wave_num)
        return fallback, len(fallback) == 0

    def _heuristic_next_wave(self, wave_num: int) -> tuple[list[str], bool]:
        """Fast deterministic wave planning for internal targets."""
        unused = {
            tool_name for tool_name in self.tool_specs
            if tool_name not in self.all_raw_outputs and self.available_tools.get(tool_name, False)
        }

        def _pick(candidates: list[str]) -> list[str]:
            selected: list[str] = []
            for tool_name in candidates:
                if tool_name not in unused:
                    continue
                if self.tool_specs[tool_name].get("requires_ip") and not self.resolved_ip:
                    continue
                selected.append(tool_name)
            return selected[:3]

        if wave_num == 1:
            tools = _pick([
                "security_headers",
                "robots_passive",
                "wafw00f_check",
                "whatweb_passive",
                "ssl_check",
            ])
            return tools, False

        if wave_num == 2:
            tools = _pick([
                "whatweb_full",
                "curl_headers",
                "wayback_check",
                "whatweb_passive",
            ])
            return tools, False

        return [], True

    def _llm_with_timeout(self, prompt: str, timeout: int = 90) -> str:
        """
        Runs self.llm.invoke(prompt) in a thread.
        Returns raw string response or "" on timeout/error.
        """
        import concurrent.futures as _cf

        class _DaemonThreadPoolExecutor(_cf.ThreadPoolExecutor):
            """ThreadPoolExecutor variant whose workers are daemonized."""

            def _adjust_thread_count(self):
                if self._idle_semaphore.acquire(timeout=0):
                    return

                def weakref_cb(_, q=self._work_queue):
                    q.put(None)

                num_threads = len(self._threads)
                if num_threads < self._max_workers:
                    thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
                    worker = threading.Thread(
                        name=thread_name,
                        target=concurrent.futures.thread._worker,
                        args=(
                            weakref.ref(self, weakref_cb),
                            self._work_queue,
                            self._initializer,
                            self._initargs,
                        ),
                    )
                    worker.daemon = True
                    worker.start()
                    self._threads.add(worker)
                    concurrent.futures.thread._threads_queues[worker] = self._work_queue

        ex = _DaemonThreadPoolExecutor(max_workers=1)
        future = ex.submit(self.llm.invoke, prompt)
        try:
            response = future.result(timeout=timeout)
            return response.content if hasattr(response, "content") else str(response)
        except _cf.TimeoutError:
            self.log_warning(f"LLM decision timed out after {timeout}s — using heuristic fallback")
            future.cancel()
            return ""
        except Exception as e:
            self.log_warning(f"LLM call failed: {e}")
            return ""
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    def _fallback_next_tools(self, wave_num: int) -> list[str]:
        """Deterministic fallback when LLM decision is unavailable."""
        candidates: list[str] = []
        target_type = self._detect_target_type()

        if target_type == "internal":
            if wave_num == 1:
                candidates = ["security_headers", "robots_passive", "wafw00f_check"]
            elif wave_num == 2:
                candidates = ["whatweb_passive", "wayback_check"]
        else:
            if wave_num == 1:
                candidates = ["whois_ip", "reverse_dns", "subfinder_passive"]
            elif wave_num == 2:
                candidates = ["theharvester_ddg", "mx_lookup", "cert_transparency"]

        unique: list[str] = []
        for tool_name in candidates:
            if tool_name not in self.tool_specs:
                continue
            if tool_name in self.all_raw_outputs:
                continue
            if not self.available_tools.get(tool_name, False):
                continue
            if self.tool_specs[tool_name].get("requires_ip") and not self.resolved_ip:
                continue
            if tool_name not in unique:
                unique.append(tool_name)
        return unique[:self.MAX_CONCURRENT]

    def _extract_json_dict(self, text: str) -> dict[str, Any] | None:
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for idx, char in enumerate(text[start:], start):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    block = text[start: idx + 1]
                    try:
                        data = json.loads(block)
                        if isinstance(data, dict):
                            return data
                    except json.JSONDecodeError:
                        return None
        return None

    def _summarize_wave_output(self, wave_results: dict[str, str]) -> str:
        lines = []
        for tool_name, output in wave_results.items():
            if not output or output.startswith("[ERROR") or output.startswith("[TIMEOUT"):
                lines.append(f"[{tool_name}] failed/timeout")
                continue
            preview = output[:400].replace("\n", " | ")
            lines.append(f"[{tool_name}] {preview}")
        return "\n".join(lines)

    def _extract_ip_from_dns(self, dns_output: str) -> str | None:
        for candidate in self._IP_RE.findall(dns_output or ""):
            if self._is_valid_ipv4(candidate):
                return candidate
        try:
            candidate = socket.gethostbyname(self.target)
            if self._is_valid_ipv4(candidate):
                return candidate
        except OSError:
            pass
        return None

    def _extract_findings_from_wave(self, wave_results: dict[str, str], wave_num: int):
        del wave_num
        for tool_name, output in wave_results.items():
            if (
                not output
                or output.startswith("[SKIPPED")
                or output.startswith("[ERROR")
                or output.startswith("[TOOL_NOT_AVAILABLE]")
                or output.startswith("[TIMEOUT")
            ):
                continue

            if tool_name in {"dns_resolve", "dns_all_records", "mx_lookup", "ns_lookup", "txt_lookup", "spf_check"}:
                self._parse_dns_output(output, tool_name)
            elif tool_name in {"whois_domain", "whois_ip", "asn_lookup"}:
                self._parse_whois_output(output, tool_name)
            elif tool_name == "cert_transparency":
                self._parse_cert_transparency(output, tool_name)
            elif tool_name in {"subfinder_passive", "amass_passive"}:
                self._parse_subdomain_output(output, tool_name)
            elif tool_name == "dnsx_resolve":
                self._parse_dns_output(output, tool_name)
                self._parse_subdomain_output(output, tool_name)
            elif tool_name in {"theharvester_ddg", "theharvester_bing"}:
                self._parse_theharvester_output(output, tool_name)
            elif tool_name in {"whatweb_passive", "whatweb_full"}:
                self._parse_whatweb_output(output, tool_name)
            elif tool_name in {"security_headers", "curl_headers", "ssl_check"}:
                self._parse_security_headers(output, tool_name)
            elif tool_name == "reverse_dns":
                self._parse_reverse_dns(output, tool_name)
            elif tool_name == "wayback_check":
                self._parse_wayback_output(output, tool_name)
            elif tool_name == "wafw00f_check":
                self._parse_waf_output(output, tool_name)
            elif tool_name == "robots_passive":
                self._parse_robots_output(output, tool_name)
            elif tool_name == "host_lookup":
                self._parse_dns_output(output, tool_name)

    def _parse_dns_output(self, output: str, source: str):
        for ip in self._extract_ips(output):
            hostname = self.target if source in {"dns_resolve", "dns_all_records", "host_lookup"} else ""
            self._add_host(ip=ip, hostname=hostname, source=source)

        for match in re.finditer(r"^\s*\d+\s+([A-Za-z0-9._-]+\.[A-Za-z]{2,})\.?\s*$", output, re.MULTILINE):
            self._add_osint("mail_server", self._normalize_domain(match.group(1)), source)

        for match in re.finditer(r"\b(ns\d*\.[A-Za-z0-9._-]+\.[A-Za-z]{2,})\.?\b", output, re.IGNORECASE):
            self._add_osint("nameserver", self._normalize_domain(match.group(1)), source)

        for txt in re.findall(r"\"([^\"]+)\"", output):
            txt_val = txt.strip()
            if not txt_val:
                continue
            self._add_osint("txt_record", txt_val, source)
            if "spf" in txt_val.lower():
                self._add_osint("spf", txt_val, source)

    def _parse_whois_output(self, output: str, source: str):
        if not output:
            return

        net = self.all_findings["network_info"]
        org_patterns = [
            r"(?:OrgName|org-name|Organisation|Organization|Registrant Organization):\s*(.+)",
            r"(?:netname|NetName):\s*(.+)",
        ]
        country_patterns = [
            r"(?:Country|country|Registrant Country):\s*(.+)",
        ]
        range_patterns = [
            r"(?:NetRange|inetnum):\s*(.+)",
            r"(?:CIDR|route):\s*(.+)",
        ]
        registrar_patterns = [
            r"(?:Registrar|registrar):\s*(.+)",
        ]
        email_pattern = r"[\w\.\-]+@[\w\.\-]+\.[a-zA-Z]{2,}"

        def _first_match(patterns: list[str]) -> str:
            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            return ""

        if not net.get("org"):
            val = _first_match(org_patterns)
            if val:
                net["org"] = val
        if not net.get("country"):
            val = _first_match(country_patterns)
            if val:
                net["country"] = val
        if not net.get("ip_range"):
            val = _first_match(range_patterns)
            if val:
                net["ip_range"] = val
        if not net.get("registrar"):
            val = _first_match(registrar_patterns)
            if val:
                net["registrar"] = val

        # Team Cymru format line: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
        if source == "asn_lookup":
            for line in output.splitlines():
                if "|" not in line or line.lower().startswith("as"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 7:
                    continue
                net.setdefault("asn", parts[0])
                net.setdefault("ip_range", parts[2])
                net.setdefault("country", parts[3])
                net.setdefault("org", parts[6])
                break

        for email in set(re.findall(email_pattern, output)):
            self._add_osint("contact_email", email, source)

    def _parse_cert_transparency(self, output: str, source: str):
        parsed = None
        try:
            parsed = json.loads(output)
        except Exception:
            parsed = None

        if isinstance(parsed, list):
            for item in parsed[:50]:
                name_value = str(item.get("name_value", ""))
                for chunk in name_value.splitlines():
                    domain = self._normalize_domain(chunk)
                    if self._domain_in_scope(domain):
                        self._add_subdomain(domain, source)
        else:
            for match in self._DOMAIN_RE.findall(output):
                domain = self._normalize_domain(match)
                if self._domain_in_scope(domain):
                    self._add_subdomain(domain, source)

    def _parse_subdomain_output(self, output: str, source: str):
        for line in output.splitlines():
            domain = self._normalize_domain(line)
            if self._domain_in_scope(domain):
                self._add_subdomain(domain, source)

    def _parse_theharvester_output(self, output: str, source: str):
        for email in self._EMAIL_RE.findall(output):
            self._add_osint("email", email, source)

        for candidate in self._DOMAIN_RE.findall(output):
            domain = self._normalize_domain(candidate)
            if self._domain_in_scope(domain):
                self._add_subdomain(domain, source)

    def _parse_whatweb_output(self, output: str, source: str):
        for name, version in re.findall(r"([A-Za-z0-9_.+-]+)\[([^\]]+)\]", output):
            self._add_technology(name=name, version=version, evidence=f"{name}[{version}]", source=source)

        known = ("apache", "nginx", "php", "wordpress", "joomla", "drupal", "tomcat")
        lower = output.lower()
        for name in known:
            if name in lower:
                self._add_technology(name=name, version="", evidence=output[:120], source=source)

    def _parse_security_headers(self, output: str, source: str):
        if not output:
            return

        headers = self.all_findings["web_info"].setdefault("headers", {})
        for line in output.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                continue
            if key.lower() in {"server", "x-powered-by", "strict-transport-security", "content-security-policy"}:
                headers[key] = value

        server_match = re.search(r"(?im)^Server:\s*(.+)$", output, re.IGNORECASE)
        powered_match = re.search(r"(?im)^X-Powered-By:\s*(.+)$", output, re.IGNORECASE)

        if server_match:
            server = server_match.group(1).strip()
            self._add_technology(
                name="Server",
                version=server,
                evidence=f"Server header: {server}",
                source=source,
            )
            self.all_findings["web_info"]["server_header"] = server

        if powered_match:
            powered = powered_match.group(1).strip()
            self._add_technology(
                name="X-Powered-By",
                version=powered,
                evidence=f"X-Powered-By header: {powered}",
                source=source,
            )

        missing_headers = []
        for header in [
            "X-Frame-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]:
            if header.lower() not in output.lower():
                missing_headers.append(header)

        if missing_headers:
            self.all_findings["web_info"]["missing_security_headers"] = missing_headers

    def _parse_reverse_dns(self, output: str, source: str):
        for candidate in self._DOMAIN_RE.findall(output):
            domain = self._normalize_domain(candidate)
            if not domain:
                continue
            if self.resolved_ip:
                self._add_host(ip=self.resolved_ip, hostname=domain, source=source)
            self._add_osint("reverse_dns", domain, source)

    def _parse_wayback_output(self, output: str, source: str):
        try:
            data = json.loads(output)
            archived = data.get("archived_snapshots", {})
            if isinstance(archived, dict) and archived:
                closest = archived.get("closest", {})
                url = str(closest.get("url", "found")).strip() or "found"
                timestamp = str(closest.get("timestamp", "unknown")).strip() or "unknown"
                self._add_osint("wayback_snapshot", url, source, timestamp=timestamp)
            else:
                self.all_findings["web_info"]["wayback"] = "no_snapshots"
        except Exception:
            return

    def _parse_waf_output(self, output: str, source: str):
        if not output:
            return

        lower = output.lower()
        if "no waf detected" in lower or "none (none)" in lower:
            self.all_findings["web_info"]["waf"] = "none_detected"
            self.all_findings["web_info"]["waf_source"] = "wafw00f"
            return

        if "is behind" in lower:
            match = re.search(r"is behind (.+?)(?:[\n\.]|$)", output, re.IGNORECASE)
            if match:
                waf_name = match.group(1).strip()
                self.all_findings["web_info"]["waf"] = waf_name
                self._add_technology(
                    name=f"WAF: {waf_name}",
                    version="unknown",
                    evidence=output[:100],
                    source=source,
                )
                self._add_osint("waf", waf_name, source)

    def _parse_robots_output(self, output: str, source: str):
        if not output:
            return

        lower = output.lower()
        if "404" in output or "not found" in lower:
            self.all_findings["web_info"]["robots_txt"] = "not_found"
            return

        if "disallow" in output or "allow" in output:
            disallowed = [p.strip() for p in re.findall(r"Disallow:\s*(.+)", output, re.IGNORECASE)]
            allowed = [p.strip() for p in re.findall(r"Allow:\s*(.+)", output, re.IGNORECASE)]
            self.all_findings["web_info"]["robots_txt"] = {
                "disallowed_paths": disallowed,
                "allowed_paths": allowed,
            }
            for path in disallowed[:5]:
                self._add_osint("hidden_path", path, "robots_txt")

    def _add_host(self, ip: str, hostname: str, source: str):
        if not self._is_valid_ipv4(ip):
            return
        candidate = self._guarded({"ip": ip, "hostname": hostname})
        ip_clean = candidate.get("ip", "")
        host_clean = str(candidate.get("hostname", "")).strip()
        if not ip_clean:
            return
        record = {"hostname": host_clean, "ip": ip_clean, "source": source}
        if record not in self.all_findings["hosts"]:
            self.all_findings["hosts"].append(record)

    def _add_subdomain(self, domain: str, source: str):
        clean = self._normalize_domain(domain)
        if not clean:
            return
        candidate = self._guarded({"value": clean})
        value = str(candidate.get("value", "")).strip().lower()
        if not value:
            return
        if value not in self.all_findings["subdomains"]:
            self.all_findings["subdomains"].append(value)
            self._add_osint("subdomain", value, source)

    def _add_technology(self, name: str, version: str, evidence: str, source: str):
        clean_name = str(name).strip()
        clean_version = str(version).strip()
        if not clean_name:
            return
        candidate = self._guarded({"version": clean_version})
        clean_version = str(candidate.get("version", clean_version)).strip()
        record = {
            "name": clean_name,
            "version": clean_version,
            "evidence": evidence[:180],
            "source": source,
        }
        key = (record["name"].lower(), record["version"].lower())
        existing_keys = {(r["name"].lower(), r["version"].lower()) for r in self.all_findings["technologies"]}
        if key not in existing_keys:
            self.all_findings["technologies"].append(record)

    def _add_osint(self, info_type: str, value: str, source: str, **extra: Any):
        clean_value = str(value).strip()
        if not clean_value:
            return
        candidate = self._guarded({"value": clean_value})
        clean_value = str(candidate.get("value", "")).strip()
        if not clean_value:
            return
        record = {"type": info_type, "value": clean_value, "source": source, **extra}
        if record not in self.all_findings["osint_intel"]:
            self.all_findings["osint_intel"].append(record)

    def _guarded(self, data: dict[str, Any]) -> dict[str, Any]:
        guarded = self.hallucination_guard(data, "recon")
        if not isinstance(guarded, dict):
            return data
        guarded.pop("_hallucination_flags", None)
        guarded.pop("_guard_passed", None)
        guarded.pop("_validation_sources", None)
        return guarded

    def _extract_ips(self, text: str) -> list[str]:
        ips = []
        for candidate in self._IP_RE.findall(text):
            if self._is_valid_ipv4(candidate) and candidate not in ips:
                ips.append(candidate)
        return ips

    def _is_valid_ipv4(self, value: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
        except ValueError:
            return False

    def _normalize_domain(self, value: str) -> str:
        clean = str(value).strip().lower().rstrip(".")
        if clean.startswith("*."):
            clean = clean[2:]
        return clean

    def _detect_target_type(self) -> str:
        """Returns 'internal', 'domain', or 'ip'."""
        probe = self.resolved_ip or self.target
        try:
            addr = ipaddress.ip_address(probe)
            if addr.is_private:
                return "internal"
            return "ip"
        except ValueError:
            pass

        if "." not in self.target or self.target.endswith(".local"):
            return "internal"

        return "domain"

    def _target_looks_domain(self) -> bool:
        return bool(self.target) and not self._is_valid_ipv4(self.target) and "." in self.target

    def _domain_in_scope(self, domain: str) -> bool:
        if not domain:
            return False
        if not self._target_looks_domain():
            return True
        target = self._normalize_domain(self.target)
        return domain == target or domain.endswith(f".{target}")

    def _has_http_hint(self) -> bool:
        if self.target.startswith(("http://", "https://")):
            return True
        blob = "\n".join(self.all_raw_outputs.values()).lower()
        return any(token in blob for token in ("http", "https", "apache", "nginx", "web", "server"))

    def _has_mail_hint(self) -> bool:
        if any(item.get("type") == "mail_server" for item in self.all_findings["osint_intel"]):
            return True
        blob = "\n".join(self.all_raw_outputs.values()).lower()
        return " mx " in f" {blob} " or "mail" in blob

    def _compile_final_findings(self) -> dict[str, Any]:
        hosts = []
        seen_hosts = set()
        for host in self.all_findings["hosts"]:
            key = (host.get("ip", ""), host.get("hostname", ""))
            if key in seen_hosts:
                continue
            seen_hosts.add(key)
            hosts.append(host)

        if self.resolved_ip and not any(h.get("ip") == self.resolved_ip for h in hosts):
            hosts.insert(0, {"hostname": self.target, "ip": self.resolved_ip, "source": "dns_resolve"})

        subdomains = []
        seen_subs = set()
        for sub in self.all_findings["subdomains"]:
            if sub not in seen_subs:
                seen_subs.add(sub)
                subdomains.append(sub)

        technologies = []
        seen_tech = set()
        for tech in self.all_findings["technologies"]:
            key = (tech.get("name", "").lower(), tech.get("version", "").lower())
            if key in seen_tech:
                continue
            seen_tech.add(key)
            technologies.append(tech)

        osint = []
        seen_osint = set()
        for item in self.all_findings["osint_intel"]:
            key = (item.get("type", ""), item.get("value", ""), item.get("source", ""))
            if key in seen_osint:
                continue
            seen_osint.add(key)
            osint.append(item)

        ips = [h["ip"] for h in hosts if self._is_valid_ipv4(h.get("ip", ""))]

        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "hosts_found": len(hosts),
            "hosts": hosts,
            "ips": ips,
            "subdomains": subdomains,
            "technologies": technologies,
            "osint_intel": osint,
            "network_info": self.all_findings["network_info"],
            "web_info": self.all_findings["web_info"],
            "raw_tool_count": len(self.all_raw_outputs),
            "tools_used": list(self.all_raw_outputs.keys()),
            "recon_complete": True,
        }

    def _write_to_memory(self, findings: dict[str, Any]):
        if self.resolved_ip:
            self.memory.add_host(ip=self.resolved_ip, hostname=self.target)

        for host in findings.get("hosts", []):
            ip = host.get("ip", "")
            if self._is_valid_ipv4(ip):
                self.memory.add_host(ip=ip, hostname=host.get("hostname", ""))

        for tech in findings.get("technologies", []):
            self.memory.log_action(
                agent_name=self.agent_name,
                action="technology_found",
                result=f"{tech.get('name', '')} {tech.get('version', '')}".strip(),
            )

        for osint_item in findings.get("osint_intel", []):
            self.memory.store_in_chroma(
                finding_text=json.dumps(osint_item),
                metadata={
                    "type": osint_item.get("type", "osint"),
                    "agent": self.agent_name,
                    "target": self.target,
                },
            )

        for technique_id in ("T1590", "T1591", "T1592", "T1593", "T1594", "T1596"):
            self.memory.add_mitre_technique(technique_id)

        self.memory.save_state()

    def _print_summary(self, findings: dict[str, Any], waves_completed: int):
        table = Table(title="Recon Summary", border_style="cyan")
        table.add_column("Finding Type", style="bold white")
        table.add_column("Count / Value", style="cyan")

        target_label = self.target
        if findings.get("resolved_ip"):
            target_label = f"{self.target} → {findings['resolved_ip']}"

        tech_names = ", ".join(t.get("name", "") for t in findings.get("technologies", [])[:5]) or "none"
        network_info = findings.get("network_info", {})
        network_label = network_info.get("org") or network_info.get("asn") or "unknown"
        if network_info.get("ip_range"):
            network_label = f"{network_label} / {network_info['ip_range']}"

        table.add_row("Target", target_label)
        table.add_row("Hosts", str(findings.get("hosts_found", 0)))
        table.add_row("Subdomains", f"{len(findings.get('subdomains', []))} discovered")
        table.add_row("Technologies", tech_names)
        table.add_row("OSINT Intel", f"{len(findings.get('osint_intel', []))} item(s)")
        table.add_row("Network", network_label)
        table.add_row("Tools Used", f"{len(findings.get('tools_used', []))} passive tools")
        table.add_row("Waves Completed", f"{waves_completed}/{self.MAX_WAVES}")

        self.console.print(table)
