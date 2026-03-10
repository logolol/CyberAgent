"""
ToolExecutor — subprocess wrapper for all pentest tools.
Each method captures stdout/stderr, applies timeout, stores in MissionMemory,
and returns a structured dict.
"""
from __future__ import annotations
import json, logging, os, re, shlex, shutil, subprocess, sys, time
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)
TOOLS_PATH = Path(os.environ.get("TOOLS_PATH",
                  Path(__file__).parent.parent.parent / "tools"))


class ToolExecutor:
    def __init__(self, mission_memory=None):
        self.mm = mission_memory  # optional MissionMemory instance

    # ── Core runner ─────────────────────────────────────────────────────
    def run_tool(self, tool_name: str, args: list[str],
                 timeout: int = 300, env: dict | None = None) -> dict:
        """Execute a tool with a timeout and return structured result."""
        binary = shutil.which(tool_name)
        if not binary:
            alt = TOOLS_PATH / tool_name
            if alt.exists() and os.access(alt, os.X_OK):
                binary = str(alt)
        if not binary:
            return {"success": False, "error": f"Tool not found: {tool_name}",
                    "stdout": "", "stderr": "", "returncode": -1}

        cmd = [binary] + [str(a) for a in args]
        _log.info(f"[ToolExecutor] Running: {' '.join(shlex.quote(c) for c in cmd)}")
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, env={**os.environ, **(env or {})},
            )
            elapsed = time.time() - t0
            result = {
                "success": proc.returncode == 0,
                "tool": tool_name, "args": args,
                "stdout": proc.stdout, "stderr": proc.stderr,
                "returncode": proc.returncode, "elapsed": elapsed,
            }
        except subprocess.TimeoutExpired:
            result = {"success": False, "tool": tool_name,
                      "error": f"Timeout after {timeout}s",
                      "stdout": "", "stderr": "", "returncode": -1}
        except Exception as e:
            result = {"success": False, "tool": tool_name,
                      "error": str(e), "stdout": "", "stderr": "", "returncode": -1}

        if self.mm:
            self.mm.log_action(tool_name, " ".join(str(a) for a in args),
                               "ok" if result["success"] else result.get("error","failed"))
        return result

    # ── Nmap ──────────────────────────────────────────────────────────
    def run_nmap(self, target: str, flags: str = "-sV -sC -p-",
                 timeout: int = 600) -> dict:
        args = shlex.split(flags) + [target, "-oJ", "-"]
        raw = self.run_tool("nmap", args, timeout=timeout)
        ports = []
        try:
            data = json.loads(raw["stdout"])
            for host in data.get("nmaprun", {}).get("host", []):
                ip = next((a["addr"] for a in host.get("address", [])
                           if a["addrtype"] == "ipv4"), target)
                for p in host.get("ports", {}).get("port", []):
                    ports.append({
                        "port": int(p["portid"]),
                        "protocol": p.get("protocol"),
                        "state": p.get("state", {}).get("state"),
                        "service": p.get("service", {}).get("name"),
                        "version": p.get("service", {}).get("product","") + " " +
                                   p.get("service", {}).get("version",""),
                    })
                    if self.mm:
                        self.mm.add_port(ip, int(p["portid"]),
                                         service=p.get("service",{}).get("name",""),
                                         version=p.get("service",{}).get("version",""))
        except Exception:
            # fallback: parse text output
            for line in raw.get("stdout","").splitlines():
                m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(.*)", line)
                if m:
                    ports.append({"port": int(m.group(1)), "protocol": m.group(2),
                                  "state": m.group(3), "service": m.group(4)})
        raw["parsed_ports"] = ports
        return raw

    # ── Searchsploit ──────────────────────────────────────────────────
    def run_searchsploit(self, query: str) -> dict:
        args = ["--json", query]
        raw = self.run_tool("searchsploit", args, timeout=30)
        exploits = []
        try:
            data = json.loads(raw["stdout"])
            for e in data.get("RESULTS_EXPLOIT", []):
                exploits.append({
                    "title": e.get("Title"),
                    "edb_id": e.get("EDB-ID"),
                    "type": e.get("Type"),
                    "platform": e.get("Platform"),
                    "path": e.get("Path"),
                })
        except Exception:
            pass
        raw["parsed_exploits"] = exploits
        return raw

    # ── Hydra ─────────────────────────────────────────────────────────
    def run_hydra(self, target: str, service: str,
                  userlist: str, passlist: str, timeout: int = 600) -> dict:
        args = ["-L", userlist, "-P", passlist, target, service,
                "-t", "4", "-V", "-o", "/dev/stdout"]
        raw = self.run_tool("hydra", args, timeout=timeout)
        creds = []
        for line in raw.get("stdout","").splitlines():
            m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
            if m:
                creds.append({"username": m.group(1), "password": m.group(2)})
                if self.mm:
                    self.mm.add_credential(target, username=m.group(1),
                                           password=m.group(2), service=service)
        raw["found_credentials"] = creds
        return raw

    # ── SQLMap ────────────────────────────────────────────────────────
    def run_sqlmap(self, url: str, flags: str = "--batch --dbs",
                   timeout: int = 600) -> dict:
        args = ["-u", url] + shlex.split(flags)
        raw = self.run_tool("sqlmap", args, timeout=timeout)
        dbs = re.findall(r"\[\*\] (\w+)", raw.get("stdout",""))
        raw["databases_found"] = dbs
        return raw

    # ── Gobuster ──────────────────────────────────────────────────────
    def run_gobuster(self, target: str, wordlist: str,
                     mode: str = "dir", timeout: int = 300) -> dict:
        args = [mode, "-u", target, "-w", wordlist, "-q", "--no-progress"]
        raw = self.run_tool("gobuster", args, timeout=timeout)
        paths = []
        for line in raw.get("stdout","").splitlines():
            m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                paths.append({"path": m.group(1), "status": int(m.group(2))})
        raw["found_paths"] = paths
        return raw

    # ── Nikto ─────────────────────────────────────────────────────────
    def run_nikto(self, target: str, timeout: int = 600) -> dict:
        args = ["-h", target, "-Format", "json", "-output", "/dev/stdout"]
        raw = self.run_tool("nikto", args, timeout=timeout)
        vulns = []
        try:
            data = json.loads(raw["stdout"])
            for vuln in data.get("vulnerabilities", []):
                vulns.append({
                    "id": vuln.get("id"),
                    "description": vuln.get("msg"),
                    "uri": vuln.get("uri"),
                })
        except Exception:
            pass
        raw["vulnerabilities"] = vulns
        return raw

    # ── SIPVicious ────────────────────────────────────────────────────
    def run_sipvicious(self, target: str, timeout: int = 120) -> dict:
        args = [target]
        raw = self.run_tool("svmap", args, timeout=timeout)
        sip_info = {"target": target, "raw": raw.get("stdout", "")}
        return {**raw, "sip_info": sip_info}

    # ── LinPEAS deployment ─────────────────────────────────────────────
    def run_linpeas(self, shell=None, timeout: int = 300) -> dict:
        """Run linpeas locally (for local privesc assessment)."""
        linpeas_path = TOOLS_PATH / "linpeas.sh"
        if not linpeas_path.exists():
            return {"success": False, "error": "linpeas.sh not found in tools/"}
        raw = self.run_tool("bash", [str(linpeas_path)], timeout=timeout)
        # Extract key sections
        sections = {}
        current = "general"
        for line in raw.get("stdout","").splitlines():
            if "══" in line or "╔" in line:
                current = re.sub(r"[^\w\s]","",line).strip()[:50]
                sections[current] = []
            else:
                sections.setdefault(current, []).append(line)
        raw["sections"] = {k: "\n".join(v[:20]) for k,v in sections.items() if v}
        return raw

    # ── FFuf ──────────────────────────────────────────────────────────
    def run_ffuf(self, url: str, wordlist: str,
                 extra_flags: str = "", timeout: int = 300) -> dict:
        args = ["-u", url + "/FUZZ", "-w", wordlist,
                "-o", "/dev/stdout", "-of", "json"] + shlex.split(extra_flags)
        raw = self.run_tool("ffuf", args, timeout=timeout)
        results = []
        try:
            data = json.loads(raw["stdout"])
            for r in data.get("results", []):
                results.append({"url": r.get("url"), "status": r.get("status"),
                                 "length": r.get("length")})
        except Exception:
            pass
        raw["found"] = results
        return raw

    # ── WPScan ────────────────────────────────────────────────────────
    def run_wpscan(self, url: str, timeout: int = 300) -> dict:
        args = ["--url", url, "--format", "json", "--no-update"]
        raw = self.run_tool("wpscan", args, timeout=timeout)
        return raw

    # ── CrackMapExec / nxc ────────────────────────────────────────────
    def run_nxc(self, target: str, protocol: str = "smb",
                credentials: dict | None = None, timeout: int = 120) -> dict:
        args = [protocol, target]
        if credentials:
            args += ["-u", credentials.get("username",""),
                     "-p", credentials.get("password","")]
        raw = self.run_tool("nxc", args, timeout=timeout)
        return raw
