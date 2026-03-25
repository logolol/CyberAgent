"""
ServiceAnalyzer - Adaptive reasoning for unknown/custom services.

Handles services without fingerprints by analyzing behavior, inferring purpose,
and discovering vulnerabilities through RAG-driven intelligence.
"""

import logging
import re
import concurrent.futures
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ServiceCategory(Enum):
    """Inferred service categories"""
    WEB = "web"
    DATABASE = "database"
    FILE_TRANSFER = "file_transfer"
    REMOTE_ACCESS = "remote_access"
    EMAIL = "email"
    CUSTOM_API = "custom_api"
    IOT_DEVICE = "iot_device"
    SCADA_ICS = "scada_ics"
    MESSAGING = "messaging"
    UNKNOWN = "unknown"


@dataclass
class ServiceProfile:
    """Analyzed profile of an unknown service"""
    port: int
    protocol: str = "tcp"  # tcp/udp
    
    # Detection data
    banner: Optional[str] = None
    response_pattern: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    
    # Inferred properties
    category: ServiceCategory = ServiceCategory.UNKNOWN
    likely_purpose: str = ""
    technology_stack: List[str] = None
    authentication_required: bool = False
    
    # Vulnerability assessment
    attack_surface: List[str] = None  # e.g., ["input validation", "auth bypass"]
    similar_services: List[str] = None  # Known services with similar behavior
    vulnerability_patterns: List[str] = None  # Generic vuln types applicable
    
    # Reasoning
    confidence: float = 0.0  # 0-1
    reasoning: str = ""
    
    def __post_init__(self):
        if self.technology_stack is None:
            self.technology_stack = []
        if self.attack_surface is None:
            self.attack_surface = []
        if self.similar_services is None:
            self.similar_services = []
        if self.vulnerability_patterns is None:
            self.vulnerability_patterns = []


class ServiceAnalyzer:
    """
    AGI-capable service analysis for unknown/custom applications.
    
    When traditional fingerprinting fails, this analyzer:
    1. Probes service behavior with custom payloads
    2. Uses LLM to reason about service purpose
    3. Queries RAG for similar service vulnerabilities
    4. Generates adaptive attack strategies
    """
    
    def __init__(self, chroma_manager, llm_client, tool_executor=None):
        """
        Args:
            chroma_manager: ChromaManager for RAG queries
            llm_client: LLM for reasoning (qwen2.5:14b recommended)
            tool_executor: Optional ToolExecutor for active probing
        """
        self.chroma = chroma_manager
        self.llm = llm_client
        self.tool_executor = tool_executor
        
        # Analysis cache
        self._profile_cache: Dict[str, ServiceProfile] = {}
    
    def analyze_unknown_service(
        self,
        target_ip: str,
        port: int,
        protocol: str = "tcp",
        banner: Optional[str] = None,
        initial_response: Optional[str] = None,
        http_headers: Optional[Dict[str, str]] = None
    ) -> ServiceProfile:
        """
        Analyze an unknown service and build a profile.
        
        Multi-stage process:
        1. Behavioral analysis (probe responses)
        2. LLM reasoning (infer purpose and technology)
        3. RAG similarity search (find known analogues)
        4. Attack surface mapping
        
        Args:
            target_ip: Target IP address
            port: Service port
            protocol: tcp or udp
            banner: Optional banner text
            initial_response: Optional initial service response
            http_headers: Optional HTTP headers if web-like
            
        Returns:
            ServiceProfile with inferred characteristics
        """
        cache_key = f"{target_ip}:{port}"
        if cache_key in self._profile_cache:
            logger.info(f"[ServiceAnalyzer] Cache hit for {cache_key}")
            return self._profile_cache[cache_key]
        
        logger.info(f"[ServiceAnalyzer] Analyzing unknown service at {target_ip}:{port}")
        
        # Initialize profile
        profile = ServiceProfile(
            port=port,
            protocol=protocol,
            banner=banner,
            http_headers=http_headers,
            response_pattern=initial_response
        )
        
        # Stage 1: Active probing (if tool executor available)
        if self.tool_executor:
            probe_results = self._probe_service_behavior(target_ip, port, protocol)
            profile.response_pattern = probe_results.get("response_pattern", initial_response)
            profile.http_headers = profile.http_headers or probe_results.get("http_headers")
        
        # Stage 2: LLM reasoning about service purpose
        inference = self._infer_service_purpose(profile)
        profile.category = inference["category"]
        profile.likely_purpose = inference["purpose"]
        profile.technology_stack = inference["technology_stack"]
        profile.authentication_required = inference["auth_required"]
        profile.confidence = inference["confidence"]
        profile.reasoning = inference["reasoning"]
        
        # Stage 3: RAG similarity search for known analogues
        similar_services = self._find_similar_services(profile)
        profile.similar_services = similar_services
        
        # Stage 4: Attack surface and vulnerability pattern mapping
        attack_info = self._map_attack_surface(profile)
        profile.attack_surface = attack_info["attack_surface"]
        profile.vulnerability_patterns = attack_info["vulnerability_patterns"]
        
        # Cache result
        self._profile_cache[cache_key] = profile
        
        logger.info(f"[ServiceAnalyzer] Analysis complete - Category: {profile.category.value}, Confidence: {profile.confidence:.2f}")
        
        return profile
    
    def _probe_service_behavior(
        self,
        target_ip: str,
        port: int,
        protocol: str
    ) -> Dict[str, Any]:
        """
        Actively probe service with various payloads to understand behavior.
        
        Probes:
        - HTTP methods (GET, POST, OPTIONS, TRACE)
        - Common protocol greetings (FTP, SMTP, SSH, etc.)
        - Invalid/malformed input (observe error handling)
        - Special characters (test input validation)
        """
        results = {
            "response_pattern": None,
            "http_headers": None,
            "error_behavior": None
        }
        
        if not self.tool_executor:
            return results
        
        logger.debug(f"[ServiceAnalyzer] Probing {target_ip}:{port}")
        
        # HTTP probes
        http_probe = self._probe_http(target_ip, port)
        if http_probe:
            results["http_headers"] = http_probe.get("headers")
            results["response_pattern"] = http_probe.get("body_preview")
        
        # Generic TCP probes (if not HTTP)
        if not http_probe:
            tcp_probe = self._probe_tcp_generic(target_ip, port)
            results["response_pattern"] = tcp_probe.get("response")
            results["error_behavior"] = tcp_probe.get("error_behavior")
        
        return results
    
    def _probe_http(self, target_ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Probe for HTTP-like behavior"""
        try:
            # Use curl via tool executor
            result = self.tool_executor.execute_command(
                "curl",
                [
                    "-s", "-I",  # Silent, headers only
                    "-m", "5",  # 5 second timeout
                    "--max-redirs", "0",  # No redirects
                    f"http://{target_ip}:{port}/"
                ],
                timeout=6
            )
            
            if result and result.get("stdout"):
                headers = self._parse_http_headers(result["stdout"])
                return {
                    "headers": headers,
                    "body_preview": result.get("stdout", "")[:200]
                }
        
        except Exception as e:
            logger.debug(f"[ServiceAnalyzer] HTTP probe failed: {e}")
        
        return None
    
    def _parse_http_headers(self, header_text: str) -> Dict[str, str]:
        """Parse HTTP response headers"""
        headers = {}
        for line in header_text.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    
    def _probe_tcp_generic(self, target_ip: str, port: int) -> Dict[str, Any]:
        """Generic TCP probing with various payloads"""
        results = {
            "response": None,
            "error_behavior": None
        }
        
        # Try netcat with various greetings
        greetings = [
            "HELLO\r\n",
            "GET / HTTP/1.0\r\n\r\n",
            "USER anonymous\r\n",
            "\x00\x00\x00\x01",  # Binary probe
        ]
        
        for greeting in greetings:
            try:
                # Use netcat via tool executor
                result = self.tool_executor.execute_command(
                    "sh",
                    ["-c", f"echo -ne '{greeting}' | nc -w 2 {target_ip} {port}"],
                    timeout=3
                )
                
                if result and result.get("stdout"):
                    results["response"] = result["stdout"]
                    break  # Found responsive greeting
            
            except Exception as e:
                logger.debug(f"[ServiceAnalyzer] TCP probe failed: {e}")
                continue
        
        return results
    
    def _infer_service_purpose(self, profile: ServiceProfile) -> Dict[str, Any]:
        """
        Use LLM to reason about service purpose from behavioral evidence.
        
        Returns: Dict with category, purpose, technology_stack, auth_required, confidence, reasoning
        """
        # Build evidence summary
        evidence = self._build_evidence_summary(profile)
        
        prompt = f"""You are analyzing an unknown network service.

PORT: {profile.port}
PROTOCOL: {profile.protocol}

EVIDENCE:
{evidence}

TASK: Infer what this service is and its purpose.

Analyze:
1. What type of service is this? (web, database, API, file transfer, etc.)
2. What is its likely purpose/function?
3. What technology stack might it use? (languages, frameworks)
4. Does it require authentication?
5. How confident are you? (0-100%)

Respond in this format:
CATEGORY: [one of: web, database, file_transfer, remote_access, email, custom_api, iot_device, scada_ics, messaging, unknown]
PURPOSE: [1-2 sentence description of function]
TECHNOLOGY_STACK: [comma-separated list of likely technologies]
AUTH_REQUIRED: yes/no
CONFIDENCE: [0-100]
REASONING: [2-3 sentences explaining your analysis]
"""
        
        try:
            response = self._query_llm(prompt)
            return self._parse_inference_response(response)
        
        except Exception as e:
            logger.error(f"[ServiceAnalyzer] LLM inference failed: {e}")
            return self._fallback_inference(profile)
    
    def _build_evidence_summary(self, profile: ServiceProfile) -> str:
        """Build evidence summary for LLM"""
        lines = []
        
        if profile.banner:
            lines.append(f"Banner: {profile.banner[:200]}")
        
        if profile.response_pattern:
            lines.append(f"Response Pattern: {profile.response_pattern[:200]}")
        
        if profile.http_headers:
            lines.append("HTTP Headers:")
            for key, value in list(profile.http_headers.items())[:5]:
                lines.append(f"  {key}: {value}")
        
        # Port-based hints
        port_hints = self._get_port_hints(profile.port)
        if port_hints:
            lines.append(f"Port Context: {port_hints}")
        
        return "\n".join(lines) if lines else "No evidence available"
    
    def _get_port_hints(self, port: int) -> str:
        """Provide context clues based on port number"""
        common_ranges = {
            range(80, 90): "Likely web-related",
            range(443, 453): "Likely HTTPS/TLS",
            range(3000, 3100): "Common dev server ports",
            range(5000, 5100): "Common custom API ports",
            range(8000, 8100): "Common web/proxy ports",
            range(8080, 8090): "Common HTTP proxy ports",
            range(9000, 9100): "Common app server ports",
        }
        
        for port_range, hint in common_ranges.items():
            if port in port_range:
                return hint
        
        return ""
    
    def _query_llm(self, prompt: str, timeout: int = 120) -> str:
        """Query LLM with timeout protection (no ping - warmup handled elsewhere)"""
        
        def _invoke():
            response = self.llm.invoke(prompt)
            if hasattr(response, 'content'):
                return response.content
            elif isinstance(response, dict) and 'content' in response:
                return response['content']
            return str(response)
        
        # Execute with timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_invoke)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                logger.error(f"[ServiceAnalyzer] LLM query failed: timed out")
                raise TimeoutError("timed out")
            except Exception as e:
                logger.error(f"[ServiceAnalyzer] LLM query failed: {e}")
                raise
    
    def _parse_inference_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM inference response"""
        result = {
            "category": ServiceCategory.UNKNOWN,
            "purpose": "",
            "technology_stack": [],
            "auth_required": False,
            "confidence": 0.5,
            "reasoning": ""
        }
        
        # Extract category
        category_match = re.search(r'CATEGORY:\s*(\w+)', response, re.IGNORECASE)
        if category_match:
            category_str = category_match.group(1).lower()
            try:
                result["category"] = ServiceCategory(category_str)
            except ValueError:
                result["category"] = ServiceCategory.UNKNOWN
        
        # Extract purpose
        purpose_match = re.search(r'PURPOSE:\s*(.+?)(?=\n[A-Z_]+:|$)', response, re.DOTALL | re.IGNORECASE)
        if purpose_match:
            result["purpose"] = purpose_match.group(1).strip()
        
        # Extract technology stack
        tech_match = re.search(r'TECHNOLOGY_STACK:\s*(.+?)(?=\n[A-Z_]+:|$)', response, re.IGNORECASE)
        if tech_match:
            tech_text = tech_match.group(1).strip()
            result["technology_stack"] = [t.strip() for t in tech_text.split(',') if t.strip()]
        
        # Extract auth requirement
        auth_match = re.search(r'AUTH_REQUIRED:\s*(yes|no)', response, re.IGNORECASE)
        if auth_match:
            result["auth_required"] = auth_match.group(1).lower() == "yes"
        
        # Extract confidence
        conf_match = re.search(r'CONFIDENCE:\s*([\d.]+)', response, re.IGNORECASE)
        if conf_match:
            result["confidence"] = float(conf_match.group(1)) / 100.0
        
        # Extract reasoning
        reasoning_match = re.search(r'REASONING:\s*(.+?)(?=\n[A-Z_]+:|$)', response, re.DOTALL | re.IGNORECASE)
        if reasoning_match:
            result["reasoning"] = reasoning_match.group(1).strip()
        
        return result
    
    def _fallback_inference(self, profile: ServiceProfile) -> Dict[str, Any]:
        """Fallback inference when LLM fails"""
        category = ServiceCategory.UNKNOWN
        purpose = "Unknown service"
        
        # Simple port-based heuristics
        if profile.port in [80, 8080, 8000, 3000]:
            category = ServiceCategory.WEB
            purpose = "Likely web server or HTTP API"
        elif profile.port in [443, 8443]:
            category = ServiceCategory.WEB
            purpose = "Likely HTTPS web server"
        elif profile.port in [3306, 5432, 1433, 27017]:
            category = ServiceCategory.DATABASE
            purpose = "Likely database server"
        elif profile.port in [21, 22, 23]:
            category = ServiceCategory.REMOTE_ACCESS
            purpose = "Likely remote access service"
        
        return {
            "category": category,
            "purpose": purpose,
            "technology_stack": [],
            "auth_required": False,
            "confidence": 0.3,  # Low confidence
            "reasoning": "Fallback heuristic based on port number"
        }
    
    def _find_similar_services(self, profile: ServiceProfile) -> List[str]:
        """
        Query RAG for services with similar characteristics.
        
        Uses semantic search to find known services/vulnerabilities
        that match the inferred service profile.
        """
        similar = []
        
        # Build search query from profile
        query_parts = []
        
        if profile.likely_purpose:
            query_parts.append(profile.likely_purpose)
        
        if profile.technology_stack:
            query_parts.extend(profile.technology_stack)
        
        query_parts.append(profile.category.value)
        query_parts.append(f"port {profile.port}")
        
        query = " ".join(query_parts)
        
        logger.debug(f"[ServiceAnalyzer] RAG similarity search: {query}")
        
        # Query multiple collections
        collections = ["hacktricks", "cve_database", "exploitdb"]
        
        for collection in collections:
            try:
                # semantic_search returns list[dict] with keys: text, metadata, distance
                results = self.chroma.semantic_search(collection, query, n_results=3)
                
                if results:  # results is a list of dicts
                    for hit in results:
                        doc = hit.get("text", "")
                        # Extract service names from text
                        service_names = self._extract_service_names(doc)
                        similar.extend(service_names)
            
            except Exception as e:
                logger.warning(f"[ServiceAnalyzer] RAG query failed for {collection}: {e}")
        
        # Deduplicate
        similar = list(set(similar))[:5]  # Top 5
        
        return similar
    
    def _extract_service_names(self, text: str) -> List[str]:
        """Extract service/product names from text"""
        # Simple extraction: capitalized words, common service patterns
        services = []
        
        # Pattern 1: "ServiceName version"
        version_pattern = r'([A-Z][a-zA-Z0-9]+)\s+\d+\.\d+'
        services.extend(re.findall(version_pattern, text))
        
        # Pattern 2: Common service names
        common_services = [
            'Apache', 'Nginx', 'IIS', 'Tomcat', 'MySQL', 'PostgreSQL',
            'MongoDB', 'Redis', 'Jenkins', 'Wordpress', 'Joomla', 'Drupal',
            'Node.js', 'PHP', 'Python', 'Ruby', 'Java', 'Spring', 'Express'
        ]
        
        for service in common_services:
            if service.lower() in text.lower():
                services.append(service)
        
        return services
    
    def _map_attack_surface(self, profile: ServiceProfile) -> Dict[str, Any]:
        """
        Map attack surface and vulnerability patterns for the service.
        
        Uses LLM reasoning + RAG to identify:
        - Attack vectors specific to service category
        - Common vulnerability patterns
        - Exploitation strategies
        """
        prompt = f"""You are analyzing the attack surface of a service.

SERVICE PROFILE:
- Category: {profile.category.value}
- Purpose: {profile.likely_purpose}
- Technology Stack: {', '.join(profile.technology_stack)}
- Authentication Required: {profile.authentication_required}
- Port: {profile.port}
- Similar Known Services: {', '.join(profile.similar_services)}

TASK: Identify attack surface and vulnerability patterns.

Provide:
1. ATTACK_SURFACE: List of attack vectors (e.g., "input validation", "authentication bypass", "SQL injection")
2. VULNERABILITY_PATTERNS: Generic vulnerability types applicable to this service category
3. EXPLOITATION_APPROACH: High-level strategy for exploitation

Format:
ATTACK_SURFACE:
  - [vector 1]
  - [vector 2]
  - [vector 3]

VULNERABILITY_PATTERNS:
  - [pattern 1]
  - [pattern 2]
  - [pattern 3]

EXPLOITATION_APPROACH: [2-3 sentences on recommended approach]
"""
        
        try:
            response = self._query_llm(prompt)
            return self._parse_attack_surface_response(response)
        
        except Exception as e:
            logger.error(f"[ServiceAnalyzer] Attack surface mapping failed: {e}")
            return self._fallback_attack_surface(profile)
    
    def _parse_attack_surface_response(self, response: str) -> Dict[str, Any]:
        """Parse attack surface analysis"""
        result = {
            "attack_surface": [],
            "vulnerability_patterns": [],
            "exploitation_approach": ""
        }
        
        # Extract attack surface
        surface_section = re.search(
            r'ATTACK_SURFACE:\s*(.+?)(?=\n[A-Z_]+:|$)',
            response,
            re.DOTALL | re.IGNORECASE
        )
        if surface_section:
            result["attack_surface"] = re.findall(
                r'[-•*]\s*(.+)',
                surface_section.group(1)
            )
        
        # Extract vulnerability patterns
        patterns_section = re.search(
            r'VULNERABILITY_PATTERNS:\s*(.+?)(?=\n[A-Z_]+:|$)',
            response,
            re.DOTALL | re.IGNORECASE
        )
        if patterns_section:
            result["vulnerability_patterns"] = re.findall(
                r'[-•*]\s*(.+)',
                patterns_section.group(1)
            )
        
        # Extract exploitation approach
        approach_match = re.search(
            r'EXPLOITATION_APPROACH:\s*(.+?)(?=\n[A-Z_]+:|$)',
            response,
            re.DOTALL | re.IGNORECASE
        )
        if approach_match:
            result["exploitation_approach"] = approach_match.group(1).strip()
        
        return result
    
    def _fallback_attack_surface(self, profile: ServiceProfile) -> Dict[str, Any]:
        """Fallback attack surface mapping"""
        # Category-based defaults
        category_surfaces = {
            ServiceCategory.WEB: {
                "attack_surface": ["SQL injection", "XSS", "CSRF", "path traversal", "authentication bypass"],
                "vulnerability_patterns": ["input validation flaws", "session management issues", "access control errors"],
                "exploitation_approach": "Focus on input validation, authentication mechanisms, and access controls"
            },
            ServiceCategory.DATABASE: {
                "attack_surface": ["SQL injection", "authentication bypass", "weak credentials", "exposed management interfaces"],
                "vulnerability_patterns": ["authentication flaws", "privilege escalation", "data exposure"],
                "exploitation_approach": "Attempt credential brute-force, check for default passwords, exploit management interfaces"
            },
            ServiceCategory.CUSTOM_API: {
                "attack_surface": ["API authentication bypass", "parameter tampering", "mass assignment", "IDOR"],
                "vulnerability_patterns": ["broken authentication", "excessive data exposure", "injection flaws"],
                "exploitation_approach": "Test API endpoints for auth bypass, parameter manipulation, and injection vulnerabilities"
            },
            ServiceCategory.UNKNOWN: {
                "attack_surface": ["buffer overflow", "format string", "authentication bypass", "input validation"],
                "vulnerability_patterns": ["memory corruption", "logic flaws", "injection"],
                "exploitation_approach": "Use fuzzing and protocol analysis to discover vulnerabilities"
            }
        }
        
        return category_surfaces.get(profile.category, category_surfaces[ServiceCategory.UNKNOWN])
    
    def generate_custom_probes(self, profile: ServiceProfile) -> List[Dict[str, Any]]:
        """
        Generate custom probe payloads for the service.
        
        Based on service category and attack surface, creates
        adaptive probes to discover vulnerabilities.
        
        Returns:
            List of probe dicts with: name, payload, expected_indicators, vuln_if_match
        """
        probes = []
        
        # Web service probes
        if profile.category == ServiceCategory.WEB:
            probes.extend([
                {
                    "name": "SQL Injection Test",
                    "payload": "' OR '1'='1",
                    "expected_indicators": ["mysql_error", "syntax error", "unexpected behavior"],
                    "vuln_if_match": "SQL Injection"
                },
                {
                    "name": "Path Traversal Test",
                    "payload": "../../../../etc/passwd",
                    "expected_indicators": ["root:x:", "passwd file content"],
                    "vuln_if_match": "Path Traversal"
                },
                {
                    "name": "Command Injection Test",
                    "payload": "; id",
                    "expected_indicators": ["uid=", "gid=", "command output"],
                    "vuln_if_match": "Command Injection"
                }
            ])
        
        # Database service probes
        elif profile.category == ServiceCategory.DATABASE:
            probes.extend([
                {
                    "name": "Default Credentials Test",
                    "payload": "admin:admin",
                    "expected_indicators": ["authentication successful", "connected"],
                    "vuln_if_match": "Weak Default Credentials"
                },
                {
                    "name": "Anonymous Access Test",
                    "payload": "",
                    "expected_indicators": ["connected", "database list"],
                    "vuln_if_match": "Unauthenticated Access"
                }
            ])
        
        # Custom API probes
        elif profile.category == ServiceCategory.CUSTOM_API:
            probes.extend([
                {
                    "name": "Auth Bypass Test",
                    "payload": '{"admin": true}',
                    "expected_indicators": ["admin access", "elevated privileges"],
                    "vuln_if_match": "Authentication Bypass"
                },
                {
                    "name": "IDOR Test",
                    "payload": "/../../../user/1",
                    "expected_indicators": ["other user data", "unauthorized access"],
                    "vuln_if_match": "IDOR"
                }
            ])
        
        # Generic probes for unknown services
        else:
            probes.extend([
                {
                    "name": "Buffer Overflow Probe",
                    "payload": "A" * 1000,
                    "expected_indicators": ["crash", "segfault", "core dump"],
                    "vuln_if_match": "Buffer Overflow"
                },
                {
                    "name": "Format String Probe",
                    "payload": "%x%x%x%x%x",
                    "expected_indicators": ["memory addresses", "stack content"],
                    "vuln_if_match": "Format String"
                }
            ])
        
        logger.info(f"[ServiceAnalyzer] Generated {len(probes)} custom probes for {profile.category.value}")
        
        return probes
    
    def query_vulnerability_database(self, profile: ServiceProfile, max_results: int = 10) -> List[Dict[str, Any]]:
        """
        Query RAG for vulnerabilities matching the service profile.
        
        Uses inferred characteristics to find applicable CVEs and exploits.
        
        Returns:
            List of vulnerability dicts with: cve, description, cvss, exploitation_method
        """
        vulnerabilities = []
        
        # Build comprehensive query
        query_parts = [profile.category.value, profile.likely_purpose]
        query_parts.extend(profile.technology_stack)
        query_parts.extend(profile.vulnerability_patterns)
        query_parts.append("vulnerability exploit")
        
        query = " ".join(query_parts)
        
        logger.info(f"[ServiceAnalyzer] Querying vulnerability database: {query}")
        
        # Query RAG collections
        collections = ["cve_database", "exploitdb", "nuclei_templates"]
        
        for collection in collections:
            try:
                # semantic_search returns list[dict] with keys: text, metadata, distance
                results = self.chroma.semantic_search(collection, query, n_results=5)
                
                if results:  # results is a list of dicts
                    for hit in results:
                        doc = hit.get("text", "")
                        metadata = hit.get("metadata", {})
                        
                        vuln = {
                            "source": collection,
                            "description": doc[:300],
                            "cve": metadata.get("cve", metadata.get("CVE-ID", "Unknown")),
                            "cvss": metadata.get("cvss", metadata.get("CVSS", 0.0)),
                            "metadata": metadata
                        }
                        
                        vulnerabilities.append(vuln)
            
            except Exception as e:
                logger.warning(f"[ServiceAnalyzer] Vulnerability query failed for {collection}: {e}")
        
        # Sort by CVSS score
        vulnerabilities.sort(key=lambda v: float(v.get("cvss", 0)), reverse=True)
        
        logger.info(f"[ServiceAnalyzer] Found {len(vulnerabilities)} potential vulnerabilities")
        
        return vulnerabilities[:max_results]
