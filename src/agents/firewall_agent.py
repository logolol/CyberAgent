"""
FirewallDetectionAgent — detects and evades network security controls.

Capabilities:
  - Detect: iptables, fail2ban, rate limiting, IDS/IPS, WAF
  - Methods: TTL analysis, TCP fingerprinting, timing analysis, port knocking detection
  - Output: Evasion profile recommendation for other agents to use

This agent runs BEFORE exploitation to determine if stealth is needed.
"""
from __future__ import annotations

import random
import re
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from rich.panel import Panel
from rich.table import Table

_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory


class FirewallDetectionAgent(BaseAgent):
    """
    Detects firewall/IDS/IPS presence and recommends evasion strategies.
    
    Evasion profiles:
      - none: No firewall detected, full speed
      - light: Basic filtering, use -T3, avoid banned ports
      - medium: Stateful firewall, use -T2, fragment packets
      - heavy: IDS/IPS detected, use -T1, randomize, proxy
      - paranoid: Active blocking, use TOR/proxychains, max stealth
    """

    # Detection techniques and their indicators
    DETECTION_TESTS = {
        "ttl_analysis": {
            "purpose": "Detect middlebox by TTL inconsistencies",
            "weight": 0.15,
        },
        "tcp_timestamp": {
            "purpose": "Detect firewall via TCP timestamp analysis",
            "weight": 0.10,
        },
        "rst_analysis": {
            "purpose": "Analyze RST packets for firewall fingerprinting",
            "weight": 0.15,
        },
        "rate_limit_detection": {
            "purpose": "Detect rate limiting by timing analysis",
            "weight": 0.20,
        },
        "port_filtering": {
            "purpose": "Detect selective port blocking patterns",
            "weight": 0.15,
        },
        "icmp_analysis": {
            "purpose": "Analyze ICMP responses for filtering",
            "weight": 0.10,
        },
        "waf_detection": {
            "purpose": "Detect Web Application Firewall",
            "weight": 0.15,
        },
    }

    # Evasion techniques per profile level
    EVASION_PROFILES = {
        "none": {
            "nmap_timing": "-T4",
            "nmap_flags": [],
            "use_proxy": False,
            "fragment": False,
            "randomize_hosts": False,
            "delay_between_requests": 0,
            "description": "No evasion needed - full speed ahead",
        },
        "light": {
            "nmap_timing": "-T3",
            "nmap_flags": ["--max-retries", "2"],
            "use_proxy": False,
            "fragment": False,
            "randomize_hosts": False,
            "delay_between_requests": 0.1,
            "description": "Basic filtering detected - slight slowdown",
        },
        "medium": {
            "nmap_timing": "-T2",
            "nmap_flags": ["-f", "--data-length", "24"],
            "use_proxy": False,
            "fragment": True,
            "randomize_hosts": True,
            "delay_between_requests": 0.5,
            "description": "Stateful firewall - use fragmentation",
        },
        "heavy": {
            "nmap_timing": "-T1",
            "nmap_flags": ["-f", "-f", "--data-length", "32", "--randomize-hosts"],
            "use_proxy": True,
            "fragment": True,
            "randomize_hosts": True,
            "delay_between_requests": 1.0,
            "description": "IDS/IPS detected - aggressive evasion",
        },
        "paranoid": {
            "nmap_timing": "-T0",
            "nmap_flags": ["-f", "-f", "--data-length", "64", "--randomize-hosts", "--spoof-mac", "0"],
            "use_proxy": True,
            "proxy_type": "tor",
            "fragment": True,
            "randomize_hosts": True,
            "delay_between_requests": 2.0,
            "description": "Active blocking - maximum stealth via TOR",
        },
    }

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="firewall_agent",
            mission_memory=mission_memory,
            llm_role="default",
            max_react_iterations=5,
        )
        self.detection_results: dict[str, dict] = {}
        self.firewall_score = 0.0
        self.detected_technologies: list[str] = []
        
    def run(self, target: str, briefing: dict = None) -> dict:
        """
        Main entry point: detect firewalls and return evasion profile.
        
        Returns:
            {
                "agent": "firewall_agent",
                "target": str,
                "firewall_detected": bool,
                "firewall_score": float (0.0-1.0),
                "detected_technologies": ["iptables", "fail2ban", ...],
                "evasion_profile": "none|light|medium|heavy|paranoid",
                "evasion_config": {...},
                "recommendations": [...],
                "raw_results": {...}
            }
        """
        briefing = briefing or {}
        self.console.print(Panel(
            f"[bold cyan]FirewallDetectionAgent[/] analyzing [yellow]{target}[/]",
            title="🛡️ Firewall Detection"
        ))
        
        # Resolve target to IP
        target_ip = self._resolve_target(target)
        if not target_ip:
            return self._error_result(target, "Could not resolve target IP")
        
        # Run all detection tests
        self.console.print("[dim]Running detection tests...[/]")
        
        results = {}
        total_score = 0.0
        
        # 1. TTL Analysis
        ttl_result = self._detect_ttl_anomalies(target_ip)
        results["ttl_analysis"] = ttl_result
        total_score += ttl_result["score"] * self.DETECTION_TESTS["ttl_analysis"]["weight"]
        
        # 2. Rate Limit Detection
        rate_result = self._detect_rate_limiting(target_ip)
        results["rate_limit_detection"] = rate_result
        total_score += rate_result["score"] * self.DETECTION_TESTS["rate_limit_detection"]["weight"]
        
        # 3. Port Filtering Analysis
        port_result = self._detect_port_filtering(target_ip)
        results["port_filtering"] = port_result
        total_score += port_result["score"] * self.DETECTION_TESTS["port_filtering"]["weight"]
        
        # 4. ICMP Analysis
        icmp_result = self._detect_icmp_filtering(target_ip)
        results["icmp_analysis"] = icmp_result
        total_score += icmp_result["score"] * self.DETECTION_TESTS["icmp_analysis"]["weight"]
        
        # 5. RST Analysis
        rst_result = self._detect_rst_patterns(target_ip)
        results["rst_analysis"] = rst_result
        total_score += rst_result["score"] * self.DETECTION_TESTS["rst_analysis"]["weight"]
        
        # 6. WAF Detection (if HTTP ports found)
        waf_result = self._detect_waf(target_ip, target)
        results["waf_detection"] = waf_result
        total_score += waf_result["score"] * self.DETECTION_TESTS["waf_detection"]["weight"]
        
        # 7. TCP Timestamp Analysis
        ts_result = self._detect_tcp_timestamp_anomalies(target_ip)
        results["tcp_timestamp"] = ts_result
        total_score += ts_result["score"] * self.DETECTION_TESTS["tcp_timestamp"]["weight"]
        
        # Normalize and determine profile
        self.firewall_score = min(1.0, total_score)
        evasion_profile = self._determine_evasion_profile(self.firewall_score, results)
        
        # Collect detected technologies
        for test_name, test_result in results.items():
            if test_result.get("detected_tech"):
                self.detected_technologies.extend(test_result["detected_tech"])
        self.detected_technologies = list(set(self.detected_technologies))
        
        # Build recommendations
        recommendations = self._build_recommendations(evasion_profile, results)
        
        # Log to mission memory
        self._log_to_memory(target_ip, evasion_profile, results)
        
        # Display results
        self._display_results(target, evasion_profile, results)
        
        return {
            "agent": "firewall_agent",
            "target": target,
            "target_ip": target_ip,
            "firewall_detected": self.firewall_score > 0.2,
            "firewall_score": round(self.firewall_score, 3),
            "detected_technologies": self.detected_technologies,
            "evasion_profile": evasion_profile,
            "evasion_config": self.EVASION_PROFILES[evasion_profile],
            "recommendations": recommendations,
            "raw_results": results,
        }

    def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            # Check if already an IP
            socket.inet_aton(target)
            return target
        except socket.error:
            pass
        
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            self.logger.error(f"Could not resolve {target}")
            return None

    def _detect_ttl_anomalies(self, target_ip: str) -> dict:
        """
        Detect firewall/middlebox by analyzing TTL variations.
        
        Technique: Send multiple pings and analyze TTL consistency.
        Middleboxes often have different TTL than the actual target.
        """
        result = {
            "test": "ttl_analysis",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        try:
            # Send 5 pings with different packet sizes
            ttls = []
            for size in [56, 128, 512, 1024]:
                cmd = ["ping", "-c", "1", "-s", str(size), "-W", "2", target_ip]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                # Extract TTL from output
                ttl_match = re.search(r'ttl=(\d+)', proc.stdout, re.IGNORECASE)
                if ttl_match:
                    ttls.append(int(ttl_match.group(1)))
            
            if len(ttls) >= 2:
                # Calculate TTL variance
                ttl_variance = max(ttls) - min(ttls)
                
                if ttl_variance > 5:
                    result["score"] = 0.8
                    result["detected_tech"].append("middlebox")
                    result["details"] = f"TTL variance {ttl_variance} indicates middlebox/firewall"
                elif ttl_variance > 0:
                    result["score"] = 0.3
                    result["details"] = f"Minor TTL variance {ttl_variance}"
                else:
                    result["details"] = f"Consistent TTL={ttls[0]}"
                    
                # Analyze TTL value for OS/device hints
                avg_ttl = statistics.mean(ttls)
                if avg_ttl <= 64:
                    result["details"] += " (Linux-like TTL)"
                elif avg_ttl <= 128:
                    result["details"] += " (Windows-like TTL)"
                elif avg_ttl <= 255:
                    result["details"] += " (Network device TTL)"
                    
        except subprocess.TimeoutExpired:
            result["score"] = 0.5
            result["detected_tech"].append("icmp_filtered")
            result["details"] = "Ping timeout - possible ICMP filtering"
        except Exception as e:
            result["details"] = f"TTL analysis failed: {e}"
            
        return result

    def _detect_rate_limiting(self, target_ip: str) -> dict:
        """
        Detect rate limiting by measuring response time degradation.
        
        Technique: Send rapid requests and measure if latency increases.
        """
        result = {
            "test": "rate_limit_detection",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        try:
            # Measure baseline latency
            baseline_times = []
            for _ in range(3):
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    sock.connect((target_ip, 80))
                    baseline_times.append(time.time() - start)
                except:
                    pass
                finally:
                    sock.close()
                time.sleep(0.5)  # Slow baseline measurement
            
            if not baseline_times:
                # Try port 22 or 443 if 80 fails
                for port in [443, 22]:
                    for _ in range(3):
                        start = time.time()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        try:
                            sock.connect((target_ip, port))
                            baseline_times.append(time.time() - start)
                        except:
                            pass
                        finally:
                            sock.close()
                    if baseline_times:
                        break
            
            if baseline_times:
                baseline = statistics.mean(baseline_times)
                
                # Rapid burst test (10 connections quickly)
                burst_times = []
                for _ in range(10):
                    start = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    try:
                        sock.connect((target_ip, 80))
                        burst_times.append(time.time() - start)
                    except socket.timeout:
                        burst_times.append(2.0)  # Timeout = rate limited
                    except:
                        pass
                    finally:
                        sock.close()
                    time.sleep(0.05)  # Fast burst
                
                if burst_times:
                    burst_avg = statistics.mean(burst_times)
                    degradation = burst_avg / baseline if baseline > 0 else 1.0
                    
                    if degradation > 3.0:
                        result["score"] = 0.9
                        result["detected_tech"].append("rate_limiting")
                        result["detected_tech"].append("fail2ban")
                        result["details"] = f"Response degradation {degradation:.1f}x indicates rate limiting"
                    elif degradation > 1.5:
                        result["score"] = 0.5
                        result["detected_tech"].append("rate_limiting")
                        result["details"] = f"Moderate degradation {degradation:.1f}x"
                    else:
                        result["details"] = f"No rate limiting detected (degradation {degradation:.1f}x)"
            else:
                result["details"] = "Could not establish baseline connections"
                        
        except Exception as e:
            result["details"] = f"Rate limit detection failed: {e}"
            
        return result

    def _detect_port_filtering(self, target_ip: str) -> dict:
        """
        Detect selective port filtering patterns.
        
        Technique: Probe common ports and analyze response patterns.
        Filtered vs closed ports indicate firewall policy.
        """
        result = {
            "test": "port_filtering",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        # Quick nmap scan for port state analysis
        try:
            cmd = [
                "nmap", "-Pn", "-n", "--max-retries", "1",
                "-p", "21,22,23,25,80,110,139,443,445,3306,3389,8080",
                "--reason", target_ip
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse nmap output for port states
            open_ports = len(re.findall(r'(\d+)/tcp\s+open', proc.stdout))
            filtered_ports = len(re.findall(r'(\d+)/tcp\s+filtered', proc.stdout))
            closed_ports = len(re.findall(r'(\d+)/tcp\s+closed', proc.stdout))
            
            total_probed = open_ports + filtered_ports + closed_ports
            
            if filtered_ports > 0:
                filter_ratio = filtered_ports / total_probed if total_probed > 0 else 0
                
                if filter_ratio > 0.5:
                    result["score"] = 0.8
                    result["detected_tech"].append("iptables")
                    result["detected_tech"].append("stateful_firewall")
                    result["details"] = f"{filtered_ports}/{total_probed} ports filtered - heavy filtering"
                elif filter_ratio > 0.2:
                    result["score"] = 0.5
                    result["detected_tech"].append("packet_filter")
                    result["details"] = f"{filtered_ports}/{total_probed} ports filtered - selective filtering"
                else:
                    result["score"] = 0.2
                    result["details"] = f"Minimal filtering ({filtered_ports} ports)"
            else:
                result["details"] = f"No filtered ports detected ({open_ports} open, {closed_ports} closed)"
                
            # Check for SYN cookies (indicates iptables with SYNPROXY)
            if "syn-ack" in proc.stdout.lower() and filtered_ports > 3:
                result["detected_tech"].append("syn_cookies")
                result["score"] = min(1.0, result["score"] + 0.2)
                
        except subprocess.TimeoutExpired:
            result["score"] = 0.7
            result["detected_tech"].append("aggressive_filtering")
            result["details"] = "Scan timeout - aggressive filtering likely"
        except Exception as e:
            result["details"] = f"Port filter detection failed: {e}"
            
        return result

    def _detect_icmp_filtering(self, target_ip: str) -> dict:
        """
        Analyze ICMP response patterns for filtering detection.
        """
        result = {
            "test": "icmp_analysis",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        try:
            # Test different ICMP types
            icmp_tests = [
                (["ping", "-c", "1", "-W", "2", target_ip], "echo"),
                (["ping", "-c", "1", "-W", "2", "-t", "1", target_ip], "ttl_exceeded"),
            ]
            
            responses = {}
            for cmd, icmp_type in icmp_tests:
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    responses[icmp_type] = "1 received" in proc.stdout or "1 packets received" in proc.stdout
                except:
                    responses[icmp_type] = False
            
            if not responses.get("echo", False):
                result["score"] = 0.4
                result["detected_tech"].append("icmp_filtered")
                result["details"] = "ICMP echo blocked"
            else:
                result["details"] = "ICMP echo allowed"
                
            # nmap ICMP probe for more detail
            cmd = ["nmap", "-sn", "-PE", "-PP", "-PM", "-n", target_ip]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if "Host is up" in proc.stdout:
                result["details"] += ", host responds to probes"
            elif "filtered" in proc.stdout.lower():
                result["score"] = max(result["score"], 0.5)
                result["detected_tech"].append("icmp_rate_limited")
                result["details"] += ", ICMP appears rate-limited"
                
        except Exception as e:
            result["details"] = f"ICMP analysis failed: {e}"
            
        return result

    def _detect_rst_patterns(self, target_ip: str) -> dict:
        """
        Analyze TCP RST packet patterns for firewall fingerprinting.
        
        Different firewalls send RST packets with different characteristics.
        """
        result = {
            "test": "rst_analysis",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        try:
            # Use nmap with packet tracing to analyze RST behavior
            cmd = [
                "nmap", "-Pn", "-n", "-sS", "--max-retries", "1",
                "-p", "1", "--reason", target_ip  # Port 1 typically closed
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if "reset" in proc.stdout.lower():
                # Normal RST from closed port
                result["details"] = "Normal RST response from closed ports"
            elif "no-response" in proc.stdout.lower() or "filtered" in proc.stdout.lower():
                result["score"] = 0.6
                result["detected_tech"].append("drop_policy")
                result["details"] = "Packets dropped (no RST) - DROP policy firewall"
            elif "admin-prohibited" in proc.stdout.lower():
                result["score"] = 0.7
                result["detected_tech"].append("iptables_reject")
                result["details"] = "ICMP admin-prohibited - iptables REJECT rule"
                
            # Check for inconsistent RST timing (stateful inspection)
            rst_times = []
            for port in [1, 2, 3]:  # Probe closed ports
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                try:
                    sock.connect((target_ip, port))
                except socket.error:
                    pass
                finally:
                    rst_times.append(time.time() - start)
                    sock.close()
            
            if rst_times and max(rst_times) - min(rst_times) > 0.3:
                result["score"] = max(result["score"], 0.5)
                result["detected_tech"].append("stateful_inspection")
                result["details"] += " + variable RST timing (stateful)"
                
        except Exception as e:
            result["details"] = f"RST analysis failed: {e}"
            
        return result

    def _detect_waf(self, target_ip: str, target: str) -> dict:
        """
        Detect Web Application Firewall presence.
        """
        result = {
            "test": "waf_detection",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        try:
            # First check if HTTP port is open
            http_open = False
            for port in [80, 443, 8080, 8443]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    sock.connect((target_ip, port))
                    http_open = True
                    sock.close()
                    break
                except:
                    sock.close()
            
            if not http_open:
                result["details"] = "No HTTP ports open - WAF detection skipped"
                return result
            
            # Use wafw00f or nmap http-waf-detect
            wafw00f_path = subprocess.run(["which", "wafw00f"], capture_output=True, text=True)
            
            if wafw00f_path.returncode == 0:
                # Use wafw00f
                host = target if not target.startswith("http") else target
                cmd = ["wafw00f", "-a", f"http://{host}", "-o", "-"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if "is behind" in proc.stdout.lower():
                    # Extract WAF name
                    waf_match = re.search(r'is behind ([\w\s]+)', proc.stdout, re.IGNORECASE)
                    if waf_match:
                        waf_name = waf_match.group(1).strip()
                        result["score"] = 0.9
                        result["detected_tech"].append(f"waf:{waf_name}")
                        result["details"] = f"WAF detected: {waf_name}"
                elif "no waf" in proc.stdout.lower():
                    result["details"] = "No WAF detected by wafw00f"
            else:
                # Fallback: nmap http-waf-detect
                cmd = ["nmap", "-Pn", "-n", "-p", "80,443", "--script", "http-waf-detect", target_ip]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if "waf" in proc.stdout.lower() and "detected" in proc.stdout.lower():
                    result["score"] = 0.7
                    result["detected_tech"].append("waf:unknown")
                    result["details"] = "WAF detected by nmap"
                else:
                    result["details"] = "No WAF detected"
                    
            # Additional: Send malicious-looking request
            try:
                import urllib.request
                test_url = f"http://{target_ip}/test.php?id=1%27%20OR%201=1--"
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                try:
                    urllib.request.urlopen(req, timeout=5)
                except urllib.error.HTTPError as e:
                    if e.code in [403, 406, 429, 503]:
                        result["score"] = max(result["score"], 0.6)
                        result["detected_tech"].append("waf:blocking")
                        result["details"] += f" + HTTP {e.code} on SQLi probe"
                except:
                    pass
            except:
                pass
                
        except Exception as e:
            result["details"] = f"WAF detection failed: {e}"
            
        return result

    def _detect_tcp_timestamp_anomalies(self, target_ip: str) -> dict:
        """
        Analyze TCP timestamps for firewall/NAT detection.
        
        Middleboxes may modify or strip TCP timestamps.
        """
        result = {
            "test": "tcp_timestamp",
            "score": 0.0,
            "detected_tech": [],
            "details": "",
        }
        
        try:
            # Use hping3 if available for TCP timestamp analysis
            hping_path = subprocess.run(["which", "hping3"], capture_output=True, text=True)
            
            if hping_path.returncode == 0:
                # Send SYN with timestamp option
                cmd = ["hping3", "-S", "-p", "80", "-c", "3", "--tcp-timestamp", target_ip]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                # Parse timestamp values
                timestamps = re.findall(r'tsval=(\d+)', proc.stdout)
                
                if timestamps:
                    ts_values = [int(t) for t in timestamps]
                    if len(ts_values) >= 2:
                        # Check for timestamp incrementing (normal)
                        diffs = [ts_values[i+1] - ts_values[i] for i in range(len(ts_values)-1)]
                        
                        if all(d > 0 for d in diffs):
                            result["details"] = "TCP timestamps incrementing normally"
                        elif all(d == 0 for d in diffs):
                            result["score"] = 0.5
                            result["detected_tech"].append("tcp_ts_stripped")
                            result["details"] = "TCP timestamps static - may be stripped by firewall"
                        else:
                            result["score"] = 0.3
                            result["details"] = f"Irregular timestamp pattern: {diffs}"
                else:
                    result["score"] = 0.4
                    result["detected_tech"].append("tcp_ts_blocked")
                    result["details"] = "No TCP timestamp in responses"
            else:
                result["details"] = "hping3 not available - skipped TCP timestamp analysis"
                
        except subprocess.TimeoutExpired:
            result["score"] = 0.5
            result["details"] = "TCP timestamp probe timeout"
        except Exception as e:
            result["details"] = f"TCP timestamp analysis failed: {e}"
            
        return result

    def _determine_evasion_profile(self, score: float, results: dict) -> str:
        """
        Determine appropriate evasion profile based on detection results.
        """
        # Check for specific technologies that require certain profiles
        all_tech = []
        for r in results.values():
            all_tech.extend(r.get("detected_tech", []))
        
        # Paranoid: TOR required
        if any("waf" in t and "cloudflare" in t.lower() for t in all_tech):
            return "paranoid"
        
        # Heavy: IDS/IPS or aggressive rate limiting
        if "fail2ban" in all_tech or "rate_limiting" in all_tech:
            if score > 0.6:
                return "heavy"
        
        # Score-based fallback
        if score >= 0.7:
            return "heavy"
        elif score >= 0.5:
            return "medium"
        elif score >= 0.3:
            return "light"
        else:
            return "none"

    def _build_recommendations(self, profile: str, results: dict) -> list[str]:
        """Build actionable recommendations based on detection."""
        recommendations = []
        config = self.EVASION_PROFILES[profile]
        
        recommendations.append(f"Use nmap timing: {config['nmap_timing']}")
        
        if config["fragment"]:
            recommendations.append("Enable packet fragmentation (-f flag)")
        
        if config["use_proxy"]:
            if config.get("proxy_type") == "tor":
                recommendations.append("Route traffic through TOR: proxychains4 nmap ...")
            else:
                recommendations.append("Use SOCKS proxy for anonymization")
        
        if config["delay_between_requests"] > 0:
            recommendations.append(f"Add {config['delay_between_requests']}s delay between requests")
        
        if config["randomize_hosts"]:
            recommendations.append("Randomize scan order (--randomize-hosts)")
        
        # Technology-specific recommendations
        all_tech = []
        for r in results.values():
            all_tech.extend(r.get("detected_tech", []))
        
        if "fail2ban" in all_tech:
            recommendations.append("⚠️ fail2ban detected: Limit to <5 failed attempts per service")
        
        if "iptables" in all_tech:
            recommendations.append("iptables detected: Use decoy scans (-D) if possible")
        
        if any("waf" in t for t in all_tech):
            recommendations.append("WAF detected: Use payload encoding and evasion techniques")
        
        return recommendations

    def _log_to_memory(self, target_ip: str, profile: str, results: dict) -> None:
        """Log firewall detection results to MissionMemory."""
        try:
            self.memory.log_action(
                agent=self.agent_name,
                action="firewall_detection",
                result=f"Profile: {profile}, Score: {self.firewall_score:.2f}, Tech: {self.detected_technologies}"
            )
            
            # Store evasion profile for other agents to use
            if hasattr(self.memory, '_state'):
                if "evasion" not in self.memory._state:
                    self.memory._state["evasion"] = {}
                self.memory._state["evasion"] = {
                    "profile": profile,
                    "config": self.EVASION_PROFILES[profile],
                    "detected_tech": self.detected_technologies,
                    "score": self.firewall_score,
                }
        except Exception as e:
            self.logger.warning(f"Could not log to memory: {e}")

    def _display_results(self, target: str, profile: str, results: dict) -> None:
        """Display detection results in a nice table."""
        table = Table(title=f"🛡️ Firewall Detection Results for {target}")
        table.add_column("Test", style="cyan")
        table.add_column("Score", style="yellow")
        table.add_column("Detected", style="red")
        table.add_column("Details", style="dim")
        
        for test_name, test_result in results.items():
            score = test_result.get("score", 0)
            score_str = f"{score:.1f}" if score > 0 else "-"
            tech = ", ".join(test_result.get("detected_tech", [])) or "-"
            details = test_result.get("details", "")[:50]
            table.add_row(test_name, score_str, tech, details)
        
        self.console.print(table)
        
        # Profile summary
        profile_config = self.EVASION_PROFILES[profile]
        self.console.print(Panel(
            f"[bold]Evasion Profile:[/] [yellow]{profile.upper()}[/]\n"
            f"[dim]{profile_config['description']}[/]\n\n"
            f"[bold]Overall Score:[/] {self.firewall_score:.2f}\n"
            f"[bold]Detected:[/] {', '.join(self.detected_technologies) or 'None'}",
            title="📋 Recommendation"
        ))

    def _error_result(self, target: str, error: str) -> dict:
        """Return error result structure."""
        return {
            "agent": "firewall_agent",
            "target": target,
            "firewall_detected": False,
            "firewall_score": 0.0,
            "detected_technologies": [],
            "evasion_profile": "none",
            "evasion_config": self.EVASION_PROFILES["none"],
            "recommendations": [],
            "error": error,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Helper function for other agents to get evasion config
# ═══════════════════════════════════════════════════════════════════════════════

def get_evasion_nmap_flags(mission_memory: MissionMemory) -> list[str]:
    """
    Get nmap evasion flags from MissionMemory.
    
    Call this from ReconAgent/EnumVulnAgent to apply detected evasion profile.
    """
    try:
        evasion = mission_memory._state.get("evasion", {})
        config = evasion.get("config", {})
        
        flags = []
        if config.get("nmap_timing"):
            flags.append(config["nmap_timing"])
        flags.extend(config.get("nmap_flags", []))
        
        return flags
    except:
        return []


def should_use_proxy(mission_memory: MissionMemory) -> bool:
    """Check if proxy should be used based on firewall detection."""
    try:
        evasion = mission_memory._state.get("evasion", {})
        return evasion.get("config", {}).get("use_proxy", False)
    except:
        return False
