"""
CyberAgent Output Schemas — Pydantic models for every agent output.
Each schema enforces the JSON contract between agents and MissionMemory.
"""

from __future__ import annotations
from typing import Optional, List, Literal, Any
from pydantic import BaseModel, Field, field_validator


# ─── SHARED SUB-MODELS ───────────────────────────────────────────────────────

class MitreTechnique(BaseModel):
    id: str = Field(..., description="MITRE ATT&CK technique ID e.g. T1046")
    name: str = Field(..., description="Technique name e.g. Network Service Discovery")
    tactic: str = Field(..., description="Parent tactic e.g. TA0007 Discovery")


class ToolSource(BaseModel):
    tool: str = Field(..., description="Tool name e.g. nmap, sqlmap, nuclei")
    command: str = Field(..., description="Exact command run")
    output_line: str = Field(..., description="Relevant output line proving the finding")


# ─── ORCHESTRATOR SCHEMA ─────────────────────────────────────────────────────

class AgentTask(BaseModel):
    objective: str = Field(..., description="Specific task for the delegated agent")
    target: str = Field(..., description="IP or hostname")
    technique: str = Field(..., description="Attack technique name")
    mitre_id: str = Field(..., description="MITRE technique ID")
    tools: List[str] = Field(..., description="Tools the agent should use")
    parameters: dict = Field(default_factory=dict, description="Tool-specific parameters")
    priority: Literal["critical", "high", "medium", "low"]
    timeout_seconds: int = Field(default=300, ge=30, le=3600)
    success_criteria: str = Field(..., description="What constitutes task completion")


class OrchestratorOutput(BaseModel):
    agent: Literal["orchestrator_agent"]
    mission_phase: str = Field(..., description="Current mission phase")
    reasoning_summary: str = Field(..., description="2-3 sentence decision explanation")
    delegate_to: Literal[
        "recon_agent", "enum_agent", "vuln_agent", "exploit_agent",
        "privesc_agent", "postexploit_agent", "report_agent"
    ]
    task: AgentTask
    next_phase_condition: str = Field(..., description="What must happen to advance phase")
    attack_chain_step: int = Field(..., ge=1, description="Current step in attack chain")
    confidence: float = Field(..., ge=0.0, le=1.0)
    blocked_vectors: List[str] = Field(default_factory=list, description="Failed techniques to avoid")


# ─── RECON SCHEMA ────────────────────────────────────────────────────────────

class ReconFinding(BaseModel):
    type: Literal["subdomain", "ip", "email", "technology", "open_port", "asn", "certificate"]
    value: str
    source: str = Field(..., description="Tool that found this")
    confidence: float = Field(..., ge=0.0, le=1.0)


class AttackSurface(BaseModel):
    subdomains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    cloud_providers: List[str] = Field(default_factory=list)


class ReconOutput(BaseModel):
    agent: Literal["recon_agent"]
    phase: Literal["recon"]
    target: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: List[ReconFinding]
    attack_surface: AttackSurface
    mitre_techniques: List[str] = Field(
        default=["T1590", "T1591", "T1592", "T1593", "T1594"],
        description="MITRE technique IDs used"
    )
    recommended_action: str
    next_agent: Literal["enum_agent"]
    requires_verification: bool = False
    sources: List[ToolSource] = Field(default_factory=list)


# ─── ENUMERATION SCHEMA ──────────────────────────────────────────────────────

class ServiceDetail(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    service: str
    version: str = Field(..., description="Exact version string from banner or -sV output")
    banner: str = Field(default="", description="Raw service banner")
    interesting_findings: List[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)


class WebPath(BaseModel):
    path: str
    status_code: int
    size: int
    redirect_to: Optional[str] = None
    interesting: bool = False
    notes: str = ""


class EnumOutput(BaseModel):
    agent: Literal["enum_agent"]
    phase: Literal["enum"]
    target: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    services: List[ServiceDetail]
    web_paths: List[WebPath] = Field(default_factory=list)
    smb_shares: List[str] = Field(default_factory=list)
    voip_extensions: List[str] = Field(default_factory=list)
    users_found: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default=["T1046", "T1135", "T1049"])
    recommended_action: str
    next_agent: Literal["vuln_agent"]
    high_value_targets: List[str] = Field(default_factory=list)
    requires_verification: bool = False
    sources: List[ToolSource] = Field(default_factory=list)


# ─── VULNERABILITY SCAN SCHEMA ───────────────────────────────────────────────

class Vulnerability(BaseModel):
    cve: str = Field(..., description="CVE-YYYY-NNNNN or 'CVE-UNKNOWN' if unconfirmed")
    cvss: float = Field(..., ge=0.0, le=10.0, description="CVSS v3.1 base score from NVD exactly")
    cvss_vector: str = Field(..., description="Full CVSS v3.1 vector string")
    service: str
    port: int = Field(..., ge=1, le=65535)
    version: str = Field(..., description="Affected version as observed in tool output")
    exploitable: bool = Field(..., description="Only true if exploit PoC confirmed or tool verified")
    exploit_path: str = Field(
        default="",
        description="EDB-ID:NNNNN or metasploit/module/path or empty if unknown"
    )
    mitre_id: str = Field(..., description="Primary MITRE ATT&CK technique ID")
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: Literal["NVD", "ExploitDB", "Nuclei", "Nikto", "WPScan", "Manual"]
    requires_verification: bool = True

    @field_validator("cve")
    @classmethod
    def cve_format(cls, v: str) -> str:
        import re
        if v != "CVE-UNKNOWN" and not re.match(r"CVE-\d{4}-\d{4,7}$", v):
            raise ValueError(f"Invalid CVE format: {v}. Use CVE-YYYY-NNNNN or CVE-UNKNOWN")
        return v


class VulnOutput(BaseModel):
    agent: Literal["vuln_agent"]
    phase: Literal["vuln"]
    target: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    vulnerabilities: List[Vulnerability]
    exploit_priority: List[str] = Field(
        ...,
        description="Ordered list: 'CVE-YYYY-NNNNN (CVSS X.X) — reason'"
    )
    mitre_techniques: List[str] = Field(default=["T1190", "T1203", "T1068"])
    recommended_action: str
    next_agent: Literal["exploit_agent"]
    sources: List[ToolSource] = Field(default_factory=list)


# ─── EXPLOITATION SCHEMA ─────────────────────────────────────────────────────

class ExploitResult(BaseModel):
    cve: Optional[str] = Field(None, description="CVE exploited or null if generic technique")
    technique: str
    tool: str
    command: str = Field(..., description="Exact command executed")
    success: bool
    shell_obtained: bool
    shell_type: Optional[Literal["reverse", "bind", "web", "interactive"]] = None
    shell_user: Optional[str] = Field(None, description="User context: www-data, user, root")
    shell_connection: Optional[str] = Field(None, description="IP:PORT for reverse shells")
    evidence: str = Field(..., description="Exact tool output or command result proving success")
    mitre_id: str


class ActiveShell(BaseModel):
    host: str
    port: int
    user: str
    shell_type: str
    connection: str


class ExploitOutput(BaseModel):
    agent: Literal["exploit_agent"]
    phase: Literal["exploit"]
    target: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    exploitation_results: List[ExploitResult]
    credentials_found: List[dict] = Field(
        default_factory=list,
        description="[{username, password, service}] discovered during exploitation"
    )
    shells_active: List[ActiveShell] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default=["T1190", "T1059", "T1078"])
    recommended_action: str
    next_agent: Literal["privesc_agent", "report_agent"]
    requires_verification: bool = False
    sources: List[ToolSource] = Field(default_factory=list)


# ─── PRIVILEGE ESCALATION SCHEMA ─────────────────────────────────────────────

class PrivEscAttempt(BaseModel):
    technique: str = Field(..., description="Technique name e.g. SUID python3, sudo vim")
    command: str
    success: bool
    reason: str = Field(..., description="Why it succeeded or failed")
    output: str = Field(default="", description="Tool output")


class SuccessfulPrivEsc(BaseModel):
    technique: str
    command: str
    cve: Optional[str] = None
    gtfobins_entry: Optional[str] = None
    mitre_id: str
    evidence: str = Field(..., description="id output confirming uid=0(root)")


class PrivEscOutput(BaseModel):
    agent: Literal["privesc_agent"]
    phase: Literal["privesc"]
    target: str
    initial_user: str = Field(..., description="User before escalation")
    final_user: str = Field(..., description="User after escalation (root if successful)")
    confidence: float = Field(..., ge=0.0, le=1.0)
    techniques_tried: List[PrivEscAttempt]
    successful_technique: Optional[SuccessfulPrivEsc] = None
    root_achieved: bool
    mitre_techniques: List[str] = Field(default=["T1548", "T1068", "T1611"])
    next_agent: Literal["postexploit_agent", "report_agent"]
    sources: List[str] = Field(default_factory=list, description="GTFOBins:binary, HackTricks:section")


# ─── POST-EXPLOITATION SCHEMA ─────────────────────────────────────────────────

class LootItem(BaseModel):
    type: Literal["credential", "ssh_key", "config", "hash", "database_dump", "network_map", "env_file"]
    content: str = Field(..., description="Actual loot content or [REDACTED] if sensitive")
    file_path: str
    service: str = ""
    cracked: bool = False


class HarvestedCredential(BaseModel):
    username: str
    password_or_hash: str
    service: str
    cracked: bool = False
    hash_type: Optional[str] = None


class PivotTarget(BaseModel):
    ip: str
    open_ports: List[int] = Field(default_factory=list)
    hostname: str = ""
    note: str = ""
    reachable: bool = True


class PostExploitOutput(BaseModel):
    agent: Literal["postexploit_agent"]
    phase: Literal["postexploit"]
    target: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    loot: List[LootItem]
    credentials_harvested: List[HarvestedCredential] = Field(default_factory=list)
    pivot_targets: List[PivotTarget] = Field(default_factory=list)
    persistence_paths: List[str] = Field(
        default_factory=list,
        description="Persistence mechanisms found or established"
    )
    mitre_techniques: List[str] = Field(default=["T1003", "T1552", "T1021", "T1083"])
    next_agent: Literal["report_agent"]
    sources: List[ToolSource] = Field(default_factory=list)


# ─── REPORTING SCHEMA ─────────────────────────────────────────────────────────

class ExecutiveSummary(BaseModel):
    critical_count: int = Field(..., ge=0)
    high_count: int = Field(..., ge=0)
    medium_count: int = Field(..., ge=0)
    low_count: int = Field(..., ge=0)
    info_count: int = Field(..., ge=0)
    top_risk: str = Field(..., description="Most critical finding in plain English")
    business_impact: str
    remediation_priorities: List[str] = Field(..., description="Top 3 fixes in priority order")


class AttackChainStep(BaseModel):
    step: int = Field(..., ge=1)
    action: str
    mitre_id: str
    tool_used: str
    evidence_ref: str


class FindingReport(BaseModel):
    id: str = Field(..., description="FINDING-001, FINDING-002, etc.")
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: str = Field(..., description="Full AV:N/AC:L/... vector")
    cve: Optional[str] = Field(None, description="CVE-YYYY-NNNNN or null")
    cwe: Optional[str] = Field(None, description="CWE-NNNN if applicable")
    mitre_id: str
    host: str
    port: int
    service: str
    description: str = Field(..., description="Technical vulnerability description")
    evidence: str = Field(..., description="Exact command output proving exploitability")
    business_impact: str = Field(..., description="Non-technical impact statement")
    remediation: str = Field(..., description="Specific fix: version/config/code change")
    references: List[str] = Field(..., description="NVD link, vendor advisory, CWE link")


class MitreAttackCoverage(BaseModel):
    tactics: List[str] = Field(..., description="List of TA00XX tactic IDs used")
    techniques: List[str] = Field(..., description="List of T1XXX technique IDs used")


class ReportOutput(BaseModel):
    agent: Literal["report_agent"]
    phase: Literal["report"]
    target: str
    report: dict = Field(..., description="Full report object")
    sources: List[str] = Field(
        default=["PTES", "OWASP-WSTG", "MITRE-ATT&CK", "NVD"],
        description="Standards and references used"
    )


# ─── SCHEMA REGISTRY ─────────────────────────────────────────────────────────

AGENT_OUTPUT_SCHEMAS = {
    "orchestrator_agent": OrchestratorOutput,
    "recon_agent": ReconOutput,
    "enum_agent": EnumOutput,
    "vuln_agent": VulnOutput,
    "exploit_agent": ExploitOutput,
    "privesc_agent": PrivEscOutput,
    "postexploit_agent": PostExploitOutput,
    "report_agent": ReportOutput,
}


def validate_agent_output(agent_name: str, data: dict) -> BaseModel:
    """
    Validate agent JSON output against its Pydantic schema.
    
    Args:
        agent_name: Agent identifier
        data: Parsed JSON dict from agent
    
    Returns:
        Validated Pydantic model instance
    
    Raises:
        ValueError: If agent unknown
        pydantic.ValidationError: If schema validation fails
    """
    if agent_name not in AGENT_OUTPUT_SCHEMAS:
        raise ValueError(f"Unknown agent: {agent_name}. Available: {list(AGENT_OUTPUT_SCHEMAS.keys())}")
    schema_class = AGENT_OUTPUT_SCHEMAS[agent_name]
    return schema_class(**data)


def get_schema_json(agent_name: str) -> str:
    """Return JSON schema for an agent's output as a string (for prompt injection)."""
    if agent_name not in AGENT_OUTPUT_SCHEMAS:
        raise ValueError(f"Unknown agent: {agent_name}")
    import json
    schema = AGENT_OUTPUT_SCHEMAS[agent_name].model_json_schema()
    return json.dumps(schema, indent=2)


def list_schemas() -> list[str]:
    """Return all agent schema names."""
    return list(AGENT_OUTPUT_SCHEMAS.keys())
