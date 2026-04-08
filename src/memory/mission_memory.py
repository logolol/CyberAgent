"""
MissionMemory — persistent per-target state tracker.
Stores scan findings in JSON + ChromaDB for LLM context injection.
"""
from __future__ import annotations
import json, logging, os, sys
import fcntl  # File locking for thread-safety
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

MISSIONS_ROOT = Path(
    os.environ.get("MISSIONS_PATH",
                   Path(__file__).parent.parent.parent / "memory" / "missions")
)


class MissionMemory:
    def __init__(self, target_domain: str):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        safe_target = target_domain.replace(".", "_").replace("/", "_").replace(":", "_")
        self.mission_id = f"{safe_target}_{ts}"
        self.target = target_domain
        self.mission_dir = MISSIONS_ROOT / self.mission_id
        self.mission_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.mission_dir / "state.json"

        self._state: dict[str, Any] = {
            "mission_id": self.mission_id,
            "target": target_domain,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "phase": "recon",
            "status": "running",
            "hosts": {},
            "attack_chain": [],
            "attack_graph": {"nodes": []},  # Prioritized exploit targets
            "mitre_techniques": [],
            "current_agent": "",
            "notes": [],
        }
        # Load existing or persist fresh
        if self.state_file.exists():
            self.load_state()
        else:
            self.save_state()

        # ChromaDB collection
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from chroma_manager import ChromaManager
            self._chroma = ChromaManager()
            self._col_name = f"mission_{safe_target}_{ts}"
            self._col = self._chroma.get_collection(self._col_name)
        except Exception as e:
            _log.warning(f"ChromaDB unavailable for MissionMemory: {e}")
            self._chroma = None
            self._col = None
        
        # ExperienceMemory (cross-mission learning)
        try:
            from memory.experience_memory import ExperienceMemory
            self.experience = ExperienceMemory()
            _log.info(f"ExperienceMemory loaded: {self.experience.get_all_stats()}")
        except Exception as e:
            _log.warning(f"ExperienceMemory unavailable: {e}")
            self.experience = None

    # ── Persistence ────────────────────────────────────────────────────
    def save_state(self):
        """Thread-safe JSON save with file locking."""
        lock_file = self.state_file.with_suffix(".lock")
        try:
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)  # Exclusive lock
                try:
                    # Write to temp file first (atomic write pattern)
                    tmp_file = self.state_file.with_suffix(".tmp")
                    with open(tmp_file, "w") as f:
                        json.dump(self._state, f, indent=2, default=str)
                    # Atomic rename
                    os.replace(tmp_file, self.state_file)
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)  # Release lock
        except Exception as e:
            _log.warning(f"save_state failed: {e}, falling back to direct write")
            with open(self.state_file, "w") as f:
                json.dump(self._state, f, indent=2, default=str)

    def load_state(self):
        """Thread-safe JSON load with file locking."""
        lock_file = self.state_file.with_suffix(".lock")
        try:
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_SH)  # Shared lock (allows concurrent reads)
                try:
                    with open(self.state_file) as f:
                        self._state = json.load(f)
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            _log.warning(f"load_state lock failed: {e}, direct read")
            with open(self.state_file) as f:
                self._state = json.load(f)

    @property
    def state(self) -> dict:
        """Public read-only alias for _state (used by orchestrator gate checks)."""
        return self._state

    # ── Phase / status ─────────────────────────────────────────────────
    def update_phase(self, phase: str):
        valid = {"recon","enum","vuln","exploit","privesc","postexploit","report"}
        if phase not in valid:
            raise ValueError(f"Invalid phase: {phase}. Must be one of {valid}")
        self._state["phase"] = phase
        self._append_chain("system", f"phase_change → {phase}", "ok")
        self.save_state()

    # ── Host management ────────────────────────────────────────────────
    def _ensure_host(self, ip: str):
        if ip not in self._state["hosts"]:
            self._state["hosts"][ip] = {
                "ip": ip, "hostname": "", "os": "",
                "ports": [], "vulnerabilities": [],
                "exploits_attempted": [], "shells": [],
                "credentials": [], "privesc_paths": [], "loot": [],
            }

    def add_host(self, ip: str, hostname: str = ""):
        self._ensure_host(ip)
        self._state["hosts"][ip]["hostname"] = hostname
        self.save_state()

    def add_port(self, ip: str, port: int, service: str = "",
                 version: str = "", banner: str = ""):
        # Validate port range
        try:
            port = int(port)
        except (TypeError, ValueError):
            _log.warning(f"add_port: invalid port value '{port}' — skipping")
            return
        if not (1 <= port <= 65535):
            _log.warning(f"add_port: port {port} out of range [1-65535] — skipping")
            return
        # Ensure host exists
        self._ensure_host(ip)
        # Sanitize: strip HTML tags, cap version length
        import re as _re
        version = _re.sub(r"<[^>]+>", "", str(version))[:100]
        service = str(service).strip() or "unknown"

        ports = self._state["hosts"][ip]["ports"]
        existing = [p for p in ports if p["port"] == port]
        if existing:
            existing[0].update({"service": service, "version": version, "banner": banner})
        else:
            ports.append({"port": port, "service": service,
                          "version": version, "banner": banner})
        self.save_state()

    def add_vulnerability(self, ip: str, cve: str, cvss: float,
                          description: str, exploitable: bool = False,
                          port: int = None, service: str = None, version: str = None):
        import re as _re
        # Validate and normalise CVE
        cve = str(cve).strip().upper()
        if not _re.match(r"^CVE-\d{4}-\d{4,7}$", cve):
            _log.warning(f"add_vulnerability: invalid CVE format '{cve}' → set to CVE-UNKNOWN")
            cve = "CVE-UNKNOWN"
        # Validate CVSS
        try:
            cvss = float(cvss)
            if not (0.0 <= cvss <= 10.0):
                _log.warning(f"add_vulnerability: CVSS {cvss} out of range → set to 0.0")
                cvss = 0.0
        except (TypeError, ValueError):
            _log.warning(f"add_vulnerability: CVSS '{cvss}' not a float → set to 0.0")
            cvss = 0.0
        # Validate description
        description = str(description).strip()
        if not description:
            description = "No description provided"
            _log.warning("add_vulnerability: empty description — using placeholder")
        # Validate exploitable
        exploitable = bool(exploitable)
        # Validate port
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        # Validate service/version
        service = str(service).strip() if service else None
        version = str(version).strip() if version else None

        self._ensure_host(ip)
        vuln_entry = {
            "cve": cve, "cvss": cvss, "description": description,
            "exploitable": exploitable,
        }
        # Add optional fields if provided
        if port is not None:
            vuln_entry["port"] = port
        if service:
            vuln_entry["service"] = service
        if version:
            vuln_entry["version"] = version
        
        self._state["hosts"][ip]["vulnerabilities"].append(vuln_entry)
        self.save_state()

    def add_shell(self, ip: str, shell_type: str, user: str, shell_path: str = "", 
                  port: int = 0, lport: int = 0, verified: bool = False):
        valid_types = {
            "shell", "root_shell", "meterpreter", "metasploit", "webshell",
            "reverse_shell", "bind_shell", "bindshell",
            "anon_ftp", "ftp_login", "rsh", "rexec", "telnet",
            "rce", "session", "unknown",
            "bash", "sh", "reverse", "bind", "ssh", "ssh_credential"  # Extended types
        }
        shell_type = str(shell_type).strip().lower()
        if shell_type not in valid_types:
            _log.warning(f"add_shell: unknown shell_type '{shell_type}' (keeping as-is)")
            # Do NOT change to "unknown" — keep specific type for evidence
        
        user = str(user).strip()
        if not user:
            user = "unknown"
            _log.warning("add_shell: empty user — using 'unknown'")
        _log.info(f"Shell obtained: {user}@{ip} via {shell_type} (port={port}, lport={lport}, verified={verified})")

        self._ensure_host(ip)
        shell_entry = {
            "type": shell_type, 
            "user": user, 
            "shell_path": shell_path,
            "verified": verified,  # FIX 5: Track verification status
        }
        # Store port info if provided
        if port:
            shell_entry["port"] = int(port)
        if lport:
            shell_entry["lport"] = int(lport)
        # Store IP for cross-reference
        shell_entry["ip"] = ip
        self._state["hosts"][ip]["shells"].append(shell_entry)
        self.save_state()

    def add_credential(self, ip: str, username: str = "", password: str = "",
                       hash_val: str = "", service: str = ""):
        username = str(username).strip()
        password = str(password).strip()
        hash_val = str(hash_val).strip()
        service = str(service).strip()

        if not username:
            _log.warning("add_credential: empty username — skipping")
            return
        if not password and not hash_val:
            _log.warning(f"add_credential: no password or hash for '{username}' — skipping")
            return
        if not service:
            service = "unknown"
            _log.warning("add_credential: empty service — using 'unknown'")

        # Log masked — never expose raw password to console
        masked = "*" * min(len(password), 8) if password else f"[hash:{hash_val[:8]}...]"
        _log.info(f"Credential found: {username}@{ip} ({service}) pw={masked}")

        self._ensure_host(ip)
        self._state["hosts"][ip]["credentials"].append({
            "username": username, "password": password,
            "hash": hash_val, "service": service,
        })
        self.save_state()

    def add_exploit_attempt(self, ip: str, exploit: str, result: str,
                            shell_obtained: bool = False):
        self._ensure_host(ip)
        self._state["hosts"][ip]["exploits_attempted"].append({
            "exploit": exploit, "result": result, "shell_obtained": shell_obtained,
        })
        self.save_state()

    def add_privesc_path(self, ip: str, technique: str, result: str, root: bool = False):
        self._ensure_host(ip)
        self._state["hosts"][ip]["privesc_paths"].append({
            "technique": technique, "result": result, "root": root,
        })
        self.save_state()

    def add_loot(self, ip: str, loot_type: str, content: str, path: str = ""):
        self._ensure_host(ip)
        self._state["hosts"][ip]["loot"].append({
            "type": loot_type, "content": content, "path": path,
        })
        self.save_state()

    # ── Attack chain + MITRE ───────────────────────────────────────────
    def _append_chain(self, agent: str, action: str, result: str):
        self._state["attack_chain"].append({
            "step": len(self._state["attack_chain"]) + 1,
            "agent": agent, "action": action, "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def log_action(self, agent_name: str, action: str, result: str):
        self._append_chain(agent_name, action, result)
        self.save_state()

    def add_mitre_technique(self, technique_id: str):
        if technique_id not in self._state["mitre_techniques"]:
            self._state["mitre_techniques"].append(technique_id)
            self.save_state()

    def add_note(self, note: str):
        self._state["notes"].append(note)
        self.save_state()

    # ── Evasion Configuration (from FirewallDetectionAgent) ────────────
    def set_evasion_config(
        self,
        profile: str,
        config: dict,
        detected_firewalls: list[str] | None = None
    ):
        """
        Store evasion profile and configuration from FirewallDetectionAgent.
        
        Args:
            profile: Evasion profile name (none/light/medium/heavy/paranoid)
            config: Dict with nmap_timing, nmap_flags, use_proxy, etc.
            detected_firewalls: List of detected firewall types
        """
        self._state["evasion"] = {
            "profile": profile,
            "config": config,
            "detected_firewalls": detected_firewalls or [],
            "timestamp": self._state.get("timestamp", ""),
        }
        self.save_state()
    
    def get_evasion_config(self) -> dict:
        """Get current evasion configuration."""
        return self._state.get("evasion", {"profile": "none", "config": {}})

    # ── Attack Graph management ────────────────────────────────
    # Impact weights for prioritization: root=1.0, user=0.7, service=0.4, info=0.1
    _IMPACT_WEIGHTS = {"root": 1.0, "user": 0.7, "service": 0.4, "info": 0.1}

    def add_attack_node(
        self,
        ip: str,
        port: int,
        service: str,
        version: str,
        cve: str,
        confidence: float,
        impact: str,
        evidence: str,
    ) -> str:
        """
        Add a prioritized exploit target node to the attack graph.
        Returns the node_id for later updates.
        """
        # Validate inputs
        try:
            port = int(port)
        except (TypeError, ValueError):
            _log.warning(f"add_attack_node: invalid port '{port}' — skipping")
            return ""
        confidence = max(0.0, min(1.0, float(confidence)))
        impact = impact.lower() if impact else "info"
        if impact not in self._IMPACT_WEIGHTS:
            _log.warning(f"add_attack_node: unknown impact '{impact}' → using 'info'")
            impact = "info"

        node_id = f"{ip}:{port}:{service}"
        
        # Initialize attack_graph if missing (legacy state files)
        if "attack_graph" not in self._state:
            self._state["attack_graph"] = {"nodes": []}
        
        # Check for existing node
        for existing in self._state["attack_graph"]["nodes"]:
            if existing.get("id") == node_id:
                # Update if new confidence is higher
                if confidence > existing.get("confidence", 0):
                    existing.update({
                        "version": version,
                        "cve": cve,
                        "confidence": confidence,
                        "impact": impact,
                        "evidence": evidence,
                    })
                    self.save_state()
                return node_id

        node = {
            "id": node_id,
            "ip": ip,
            "port": port,
            "service": service,
            "version": version,
            "cve": cve,
            "confidence": confidence,
            "impact": impact,
            "state": "untried",
            "evidence": evidence,
            "attempts": [],
        }
        self._state["attack_graph"]["nodes"].append(node)
        self.save_state()
        _log.info(
            f"AttackGraph: added {node_id} (conf={confidence:.2f}, impact={impact})"
        )
        return node_id

    def update_attack_node(
        self, node_id: str, state: str, result_evidence: str
    ) -> bool:
        """
        Update attack node state after exploit attempt.
        state: 'untried' | 'trying' | 'success' | 'failed'
        """
        valid_states = {"untried", "trying", "success", "failed"}
        if state not in valid_states:
            _log.warning(f"update_attack_node: invalid state '{state}'")
            return False

        if "attack_graph" not in self._state:
            return False

        for node in self._state["attack_graph"]["nodes"]:
            if node.get("id") == node_id:
                node["state"] = state
                node["attempts"].append({
                    "state": state,
                    "evidence": result_evidence[:200] if result_evidence else "",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                self.save_state()
                _log.info(f"AttackGraph: {node_id} → {state}")
                return True
        return False

    def get_prioritized_nodes(self) -> list[dict]:
        """
        Return attack nodes sorted by confidence × impact_weight, untried first.
        
        If ExperienceMemory is available, adjusts confidence using historical
        success rates for the CVE/service combination.
        """
        if "attack_graph" not in self._state:
            return []

        nodes = self._state["attack_graph"].get("nodes", [])
        
        def priority_score(n: dict) -> float:
            if n.get("state") != "untried":
                return -1.0  # Already tried → lowest priority
            conf = float(n.get("confidence", 0))
            impact = n.get("impact", "info")
            weight = self._IMPACT_WEIGHTS.get(impact, 0.1)
            
            # ════════════════════════════════════════════════════════════════
            # CROSS-MISSION LEARNING: Adjust confidence using historical data
            # ════════════════════════════════════════════════════════════════
            if self.experience:
                try:
                    cve = n.get("cve", "")
                    service = n.get("service", "")
                    
                    if cve and service:
                        historical_rate = self.experience.get_success_rate(cve, service)
                        if historical_rate > 0:
                            # Blend: 50% original confidence + 50% historical rate
                            conf = (conf + historical_rate) / 2
                            _log.debug(f"Adjusted confidence for {cve}: {conf:.2f} (historical: {historical_rate:.2f})")
                except Exception:
                    pass  # Don't let experience lookup break prioritization
            
            return conf * weight

        return sorted(nodes, key=priority_score, reverse=True)

    # ── ChromaDB integration ───────────────────────────────────────────
    def store_in_chroma(self, finding_text: str, metadata: dict):
        if not self._col:
            return
        try:
            ts = datetime.now(timezone.utc).isoformat()
            self._chroma.add_finding(
                self._col_name,
                {"text": finding_text, "timestamp": ts, **metadata},
            )
        except Exception as e:
            _log.warning(f"ChromaDB store failed: {e}")

    # ── Query helpers ──────────────────────────────────────────────────
    def get_all_hosts(self) -> dict:
        return self._state["hosts"]

    def get_phase_summary(self, phase: str) -> list[dict]:
        """Get attack chain entries relevant to a specific phase."""
        return [s for s in self._state["attack_chain"]
                if f"phase_change → {phase}" in s.get("action", "")]

    def get_full_context(self) -> str:
        """Return full mission state as text for LLM injection."""
        return json.dumps(self._state, indent=2, default=str)

    def export_json(self) -> str:
        return json.dumps(self._state, indent=2, default=str)

    # ── Resume support ─────────────────────────────────────────────────
    @classmethod
    def load_existing(cls, mission_id: str) -> "MissionMemory":
        """Load a previously saved mission by ID. Used for --resume."""
        state_file = MISSIONS_ROOT / mission_id / "state.json"
        if not state_file.exists():
            raise FileNotFoundError(
                f"Mission '{mission_id}' not found at {state_file}"
            )
        with open(state_file) as f:
            saved = json.load(f)

        obj = cls.__new__(cls)
        obj.mission_id = mission_id
        obj.target = saved["target"]
        obj.mission_dir = MISSIONS_ROOT / mission_id
        obj.state_file = state_file
        obj._state = saved
        obj._chroma = None
        obj._col = None
        obj._col_name = f"mission_{mission_id}"
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from chroma_manager import ChromaManager
            obj._chroma = ChromaManager()
            obj._col = obj._chroma.get_collection(obj._col_name)
        except Exception as e:
            _log.warning(f"ChromaDB unavailable in load_existing: {e}")
        _log.info(f"Resumed mission {mission_id} (target={obj.target})")
        return obj

    # ── Generic finding dispatch (used by BaseAgent.store_finding) ─────
    def add_finding_from_dict(self, data: dict):
        """Route a finding dict to the correct add_* method."""
        ftype = data.get("finding_type", "note")
        ip = data.get("ip", "")
        if ftype == "host":
            self.add_host(ip, data.get("hostname", ""))
        elif ftype == "port":
            self.add_port(ip, int(data.get("port", 0)), data.get("service", ""),
                          data.get("version", ""), data.get("banner", ""))
        elif ftype == "vuln":
            self.add_vulnerability(ip, data.get("cve", "CVE-UNKNOWN"),
                                   float(data.get("cvss", 0.0)),
                                   data.get("description", ""),
                                   bool(data.get("exploitable", False)))
        elif ftype == "shell":
            self.add_shell(ip, data.get("type", "unknown"), data.get("user", "unknown"))
        elif ftype == "cred":
            self.add_credential(ip, data.get("username", ""), data.get("password", ""),
                                data.get("hash", ""), data.get("service", ""))
        elif ftype == "loot":
            self.add_loot(ip, data.get("type", "unknown"), data.get("content", ""),
                          data.get("path", ""))
        else:
            self.add_note(str(data))

    # ══════════════════════════════════════════════════════════════════════════
    # LEARNING SYSTEM — Track successful techniques for cross-mission intelligence
    # ══════════════════════════════════════════════════════════════════════════
    
    def record_technique_success(
        self,
        technique_type: str,  # "exploit", "privesc", "enum", "credential"
        service: str,
        version: str,
        tool: str,
        cve: str = "",
        confidence_boost: float = 0.1,
        notes: str = "",
    ):
        """Record a successful technique for learning."""
        if "learning" not in self._state:
            self._state["learning"] = {
                "successful_techniques": [],
                "failed_techniques": [],
                "service_patterns": {},
            }
        
        entry = {
            "type": technique_type,
            "service": service,
            "version": version,
            "tool": tool,
            "cve": cve,
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notes": notes,
        }
        self._state["learning"]["successful_techniques"].append(entry)
        
        # Update service pattern confidence
        svc_key = f"{service}:{version[:20]}" if version else service
        if svc_key not in self._state["learning"]["service_patterns"]:
            self._state["learning"]["service_patterns"][svc_key] = {
                "successes": 0,
                "failures": 0,
                "best_tool": None,
                "confidence": 0.5,
            }
        
        pattern = self._state["learning"]["service_patterns"][svc_key]
        pattern["successes"] += 1
        pattern["best_tool"] = tool
        pattern["confidence"] = min(1.0, pattern["confidence"] + confidence_boost)
        
        self.save_state()
        _log.info(f"Learning: recorded success for {service} using {tool}")
    
    def record_technique_failure(
        self,
        technique_type: str,
        service: str,
        version: str,
        tool: str,
        cve: str = "",
        error: str = "",
    ):
        """Record a failed technique to avoid repeating."""
        if "learning" not in self._state:
            self._state["learning"] = {
                "successful_techniques": [],
                "failed_techniques": [],
                "service_patterns": {},
            }
        
        entry = {
            "type": technique_type,
            "service": service,
            "version": version,
            "tool": tool,
            "cve": cve,
            "success": False,
            "error": error[:200],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._state["learning"]["failed_techniques"].append(entry)
        
        # Update service pattern confidence
        svc_key = f"{service}:{version[:20]}" if version else service
        if svc_key not in self._state["learning"]["service_patterns"]:
            self._state["learning"]["service_patterns"][svc_key] = {
                "successes": 0,
                "failures": 0,
                "best_tool": None,
                "confidence": 0.5,
            }
        
        pattern = self._state["learning"]["service_patterns"][svc_key]
        pattern["failures"] += 1
        pattern["confidence"] = max(0.1, pattern["confidence"] - 0.05)
        
        self.save_state()
    
    def get_technique_recommendation(self, service: str, version: str = "") -> dict:
        """Get recommended technique based on learning history."""
        if "learning" not in self._state:
            return {"recommended_tool": None, "confidence": 0.5, "history": []}
        
        svc_key = f"{service}:{version[:20]}" if version else service
        pattern = self._state["learning"]["service_patterns"].get(svc_key, {})
        
        # Find historical successes for this service
        successes = [
            t for t in self._state["learning"]["successful_techniques"]
            if t["service"] == service
        ]
        
        return {
            "recommended_tool": pattern.get("best_tool"),
            "confidence": pattern.get("confidence", 0.5),
            "successes": pattern.get("successes", 0),
            "failures": pattern.get("failures", 0),
            "history": successes[-5:],  # Last 5 successes
        }
    
    def should_skip_technique(self, service: str, tool: str, cve: str = "") -> bool:
        """Check if a technique failed recently and should be skipped."""
        if "learning" not in self._state:
            return False
        
        # Check recent failures (last 10)
        recent_failures = self._state["learning"]["failed_techniques"][-10:]
        for failure in recent_failures:
            if (failure["service"] == service and 
                failure["tool"] == tool and
                (not cve or failure.get("cve") == cve)):
                return True
        
        return False


if __name__ == "__main__":
    from rich.console import Console
    console = Console()
    mm = MissionMemory("test.target.local")
    mm.add_host("192.168.1.1", "router.local")
    mm.add_port("192.168.1.1", 22, "ssh", "OpenSSH_8.9")
    mm.add_port("192.168.1.1", 80, "http", "nginx/1.18")
    mm.add_vulnerability("192.168.1.1", "CVE-2023-38408", 9.8, "OpenSSH pre-auth RCE", True)
    mm.log_action("recon_agent", "nmap scan of 192.168.1.1", "2 open ports found")
    mm.add_mitre_technique("T1046")
    console.print(f"[green]✓ MissionMemory created:[/] {mm.state_file}")
    console.print(f"  hosts: {list(mm.get_all_hosts().keys())}")
    console.print(f"  attack_chain steps: {len(mm._state['attack_chain'])}")
