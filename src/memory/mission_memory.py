"""
MissionMemory — persistent per-target state tracker.
Stores scan findings in JSON + ChromaDB for LLM context injection.
"""
from __future__ import annotations
import json, logging, os, sys
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

    # ── Persistence ────────────────────────────────────────────────────
    def save_state(self):
        with open(self.state_file, "w") as f:
            json.dump(self._state, f, indent=2, default=str)

    def load_state(self):
        with open(self.state_file) as f:
            self._state = json.load(f)

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
        self._ensure_host(ip)
        ports = self._state["hosts"][ip]["ports"]
        existing = [p for p in ports if p["port"] == port]
        if existing:
            existing[0].update({"service": service, "version": version, "banner": banner})
        else:
            ports.append({"port": port, "service": service,
                          "version": version, "banner": banner})
        self.save_state()

    def add_vulnerability(self, ip: str, cve: str, cvss: float,
                          description: str, exploitable: bool = False):
        self._ensure_host(ip)
        self._state["hosts"][ip]["vulnerabilities"].append({
            "cve": cve, "cvss": cvss, "description": description,
            "exploitable": exploitable,
        })
        self.save_state()

    def add_shell(self, ip: str, shell_type: str, user: str, shell_path: str = ""):
        self._ensure_host(ip)
        self._state["hosts"][ip]["shells"].append({
            "type": shell_type, "user": user, "shell_path": shell_path,
        })
        self.save_state()

    def add_credential(self, ip: str, username: str = "", password: str = "",
                       hash_val: str = "", service: str = ""):
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
        return [s for s in self._state["attack_chain"]
                if f"phase_change → {phase}" in s["action"] or True]

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
