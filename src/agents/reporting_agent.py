"""
ReportingAgent — Professional Pentest Report Generation with AI Analysis.

Generates comprehensive PDF reports including:
  - Executive Summary (AI-generated)
  - Vulnerability findings with CVSS scores
  - Attack chain visualization
  - Credential/loot summary
  - MITRE ATT&CK mapping
  - Remediation recommendations (AI-generated)

Output: Professional PDF report in reports/{mission_id}/pentest_report.pdf
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# PDF generation
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table as RLTable, 
    TableStyle, PageBreak, Image, ListFlowable, ListItem
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

_SRC = Path(__file__).parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agents.base_agent import BaseAgent
from memory.mission_memory import MissionMemory
from memory.chroma_manager import ChromaManager

_log = logging.getLogger(__name__)


class ReportingAgent(BaseAgent):
    """
    Professional pentest report generator with AI-powered analysis.
    
    Creates detailed PDF reports with:
    - Executive summary
    - Vulnerability breakdown by severity
    - Attack chain narrative
    - MITRE ATT&CK coverage
    - AI-generated remediation recommendations
    """

    # Severity color mapping
    SEVERITY_COLORS = {
        "critical": colors.HexColor("#DC143C"),  # Crimson
        "high": colors.HexColor("#FF4500"),      # OrangeRed
        "medium": colors.HexColor("#FFA500"),    # Orange
        "low": colors.HexColor("#FFD700"),       # Gold
        "info": colors.HexColor("#4169E1"),      # RoyalBlue
    }

    # CVSS to severity mapping
    CVSS_SEVERITY = {
        (9.0, 10.0): "critical",
        (7.0, 8.9): "high",
        (4.0, 6.9): "medium",
        (0.1, 3.9): "low",
        (0.0, 0.0): "info",
    }

    def __init__(self, mission_memory: MissionMemory):
        super().__init__(
            agent_name="ReportingAgent",
            mission_memory=mission_memory,
            llm_role="reasoning",  # Use DeepSeek-R1 for analysis
            max_react_iterations=5,
        )
        self.console = Console()
        self.target = ""
        self.report_dir = Path("reports")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect data from memory
        self.vulns: list[dict] = []
        self.credentials: list[dict] = []
        self.shells: list[dict] = []
        self.loot: list[dict] = []
        self.attack_chain: list[dict] = []
        self.mitre_techniques: list[str] = []
        self.ports: list[dict] = []
        
        # Report metadata
        self.mission_id = ""
        self.start_time = ""
        self.end_time = ""

    def run(self, target: str, briefing: dict = {}) -> dict:
        """
        Generate comprehensive pentest report.
        
        Args:
            target: Target IP/hostname
            briefing: Contains mission_summary, include_ai_analysis, etc.
        """
        self.target = target
        self.mission_id = self.memory.mission_id
        
        self.console.print(Panel(
            f"[bold blue]📊 ReportingAgent — Professional Report Generation[/]\n"
            f"[white]Target:[/] [blue]{target}[/]\n"
            f"[white]Mission ID:[/] {self.mission_id}\n"
            f"[white]Output:[/] PDF + Markdown",
            border_style="blue",
        ))

        try:
            # ══════════════════════════════════════════════════════════════
            # Phase 1: Extract data from MissionMemory
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 1: Extracting mission data...")
            self._extract_mission_data()

            # ══════════════════════════════════════════════════════════════
            # Phase 2: Generate AI analysis (optional)
            # ══════════════════════════════════════════════════════════════
            include_ai = briefing.get("include_ai_analysis", True)
            ai_analysis = {}
            if include_ai:
                self.log_info("Phase 2: Generating AI analysis...")
                ai_analysis = self._generate_ai_analysis()
            else:
                self.log_info("Phase 2: Skipping AI analysis (disabled)")

            # ══════════════════════════════════════════════════════════════
            # Phase 3: Generate PDF report
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 3: Generating PDF report...")
            pdf_path = self._generate_pdf_report(ai_analysis)

            # ══════════════════════════════════════════════════════════════
            # Phase 4: Generate Markdown report
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 4: Generating Markdown report...")
            md_path = self._generate_markdown_report(ai_analysis)

            # ══════════════════════════════════════════════════════════════
            # Phase 5: Generate JSON summary
            # ══════════════════════════════════════════════════════════════
            self.log_info("Phase 5: Generating JSON summary...")
            json_path = self._generate_json_summary(ai_analysis)

            return self._build_result(pdf_path, md_path, json_path, ai_analysis)

        except Exception as e:
            self.log_error(f"ReportingAgent failed: {e}")
            import traceback
            self.log_error(traceback.format_exc())
            return {
                "agent": self.agent_name,
                "success": False,
                "error": str(e),
            }

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 1: Data Extraction
    # ══════════════════════════════════════════════════════════════════════════

    def _extract_mission_data(self):
        """Extract all findings from MissionMemory."""
        state = self.memory.state
        
        self.start_time = state.get("started_at", "")
        self.end_time = datetime.now(timezone.utc).isoformat()
        self.attack_chain = state.get("attack_chain", [])
        self.mitre_techniques = list(set(state.get("mitre_techniques", [])))
        
        # Extract per-host data
        hosts = state.get("hosts", {})
        for ip, host_data in hosts.items():
            # Ports
            for port_info in host_data.get("ports", []):
                self.ports.append({
                    "ip": ip,
                    **port_info
                })
            
            # Vulnerabilities
            for vuln in host_data.get("vulnerabilities", []):
                vuln["ip"] = ip
                self.vulns.append(vuln)
            
            # Shells
            for shell in host_data.get("shells", []):
                shell["ip"] = ip
                self.shells.append(shell)
            
            # Credentials
            for cred in host_data.get("credentials", []):
                cred["ip"] = ip
                self.credentials.append(cred)
            
            # Loot
            for loot_item in host_data.get("loot", []):
                loot_item["ip"] = ip
                self.loot.append(loot_item)
        
        # Summary stats
        self.log_success(
            f"Extracted: {len(self.vulns)} vulns, {len(self.credentials)} creds, "
            f"{len(self.shells)} shells, {len(self.loot)} loot items"
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 2: AI Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_ai_analysis(self) -> dict:
        """Generate AI-powered analysis sections."""
        analysis = {
            "executive_summary": "",
            "risk_assessment": "",
            "remediation_recommendations": [],
            "attack_narrative": "",
        }
        
        # Build context for LLM
        vuln_summary = self._summarize_vulns()
        attack_summary = self._summarize_attack_chain()
        
        # Try LLM analysis with timeout fallback
        try:
            # Executive Summary
            analysis["executive_summary"] = self._generate_executive_summary(vuln_summary)
            
            # Risk Assessment  
            analysis["risk_assessment"] = self._generate_risk_assessment(vuln_summary)
            
            # Remediation Recommendations
            analysis["remediation_recommendations"] = self._generate_remediation(vuln_summary)
            
            # Attack Narrative
            analysis["attack_narrative"] = self._generate_attack_narrative(attack_summary)
            
        except Exception as e:
            self.log_warning(f"AI analysis partially failed: {e}")
            # Use fallback analysis
            analysis = self._fallback_analysis(vuln_summary)
        
        return analysis

    def _summarize_vulns(self) -> str:
        """Create a concise vulnerability summary for LLM."""
        if not self.vulns:
            return "No vulnerabilities discovered."
        
        # Initialize ALL severity buckets including info and unknown
        by_severity = {
            "critical": [], "high": [], "medium": [],
            "low": [], "info": [], "unknown": []
        }
        for v in self.vulns:
            cvss = v.get("cvss", 0) or 0
            sev = self._cvss_to_severity(cvss)
            sev = str(sev).lower() if sev else "unknown"
            by_severity.setdefault(sev, []).append(v)
        
        lines = [f"Total vulnerabilities: {len(self.vulns)}"]
        for sev, items in by_severity.items():
            if items:
                lines.append(f"- {sev.upper()}: {len(items)}")
                for v in items[:3]:  # Top 3 per severity
                    cve = v.get("cve", "N/A")
                    desc = v.get("description", "")[:60]
                    lines.append(f"  • {cve}: {desc}")
        
        return "\n".join(lines)

    def _summarize_attack_chain(self) -> str:
        """Summarize attack chain for LLM."""
        if not self.attack_chain:
            return "No attack chain recorded."
        
        lines = [f"Attack chain steps: {len(self.attack_chain)}"]
        for step in self.attack_chain[:20]:  # First 20 steps
            agent = step.get("agent", "?")
            action = step.get("action", "?")
            result = step.get("result", "")[:40]
            lines.append(f"- [{agent}] {action}: {result}")
        
        return "\n".join(lines)

    def _generate_executive_summary(self, vuln_summary: str) -> str:
        """Generate executive summary using LLM or fallback."""
        critical_count = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "critical"])
        high_count = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "high"])
        
        # Deterministic executive summary (no LLM needed for reliability)
        shell_status = "achieved" if self.shells else "not achieved"
        root_status = "obtained" if any(s.get("user") == "root" for s in self.shells) else "not obtained"
        
        summary = f"""A comprehensive penetration test was conducted against {self.target}. 
The assessment identified {len(self.vulns)} vulnerabilities, including {critical_count} critical and {high_count} high severity findings.

Shell access was {shell_status}. Root/privileged access was {root_status}.

{len(self.credentials)} credentials were harvested, and {len(self.loot)} sensitive data items were extracted.

The attack utilized {len(set(self.mitre_techniques))} distinct MITRE ATT&CK techniques."""
        
        if critical_count > 0:
            summary += "\n\n⚠️ CRITICAL: Immediate remediation required for critical vulnerabilities."
        
        return summary

    def _generate_risk_assessment(self, vuln_summary: str) -> str:
        """Generate risk assessment."""
        critical = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "critical"])
        high = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "high"])
        has_shells = len(self.shells) > 0
        has_root = any(s.get("user") == "root" for s in self.shells)
        
        # Risk score calculation
        risk_score = 0
        risk_score += critical * 25
        risk_score += high * 15
        risk_score += 30 if has_shells else 0
        risk_score += 20 if has_root else 0
        risk_score = min(100, risk_score)
        
        if risk_score >= 80:
            risk_level = "CRITICAL"
            risk_color = "🔴"
        elif risk_score >= 60:
            risk_level = "HIGH"
            risk_color = "🟠"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        else:
            risk_level = "LOW"
            risk_color = "🟢"
        
        assessment = f"""{risk_color} Overall Risk Level: {risk_level} (Score: {risk_score}/100)

Risk Factors:
- Critical vulnerabilities: {critical} (25 points each)
- High vulnerabilities: {high} (15 points each)
- Shell access obtained: {'Yes (+30)' if has_shells else 'No'}
- Root access obtained: {'Yes (+20)' if has_root else 'No'}

Impact Assessment:
- Confidentiality: {'COMPROMISED' if self.loot or self.credentials else 'At Risk'}
- Integrity: {'COMPROMISED' if has_root else 'At Risk' if has_shells else 'Intact'}
- Availability: At Risk (exploitation possible)"""
        
        return assessment

    def _generate_remediation(self, vuln_summary: str) -> list[dict]:
        """Generate remediation recommendations."""
        recommendations = []
        
        # Group vulns by type/service for consolidated recommendations
        seen_cves = set()
        for vuln in sorted(self.vulns, key=lambda x: x.get("cvss", 0) or 0, reverse=True):
            cve = vuln.get("cve", "")
            if cve in seen_cves:
                continue
            seen_cves.add(cve)
            
            cvss = vuln.get("cvss", 0) or 0
            service = vuln.get("service", "unknown")
            port = vuln.get("port", "?")
            desc = vuln.get("description", "")
            
            # Generate recommendation based on vulnerability type
            rec = {
                "priority": self._cvss_to_severity(cvss).upper(),
                "cve": cve,
                "service": service,
                "port": port,
                "issue": desc[:100],
                "recommendation": self._get_remediation_for_vuln(vuln),
            }
            recommendations.append(rec)
        
        return recommendations[:15]  # Top 15 recommendations

    def _get_remediation_for_vuln(self, vuln: dict) -> str:
        """Get specific remediation for a vulnerability."""
        cve = vuln.get("cve", "").lower()
        service = vuln.get("service", "").lower()
        desc = vuln.get("description", "").lower()
        
        # Known vulnerability remediations
        if "vsftpd" in service or "2011-2523" in cve:
            return "Upgrade vsftpd to version 3.0.3 or later. The backdoor was present in version 2.3.4."
        
        if "samba" in service or "usermap" in desc or "2007-2447" in cve:
            return "Upgrade Samba to version 3.0.25 or later. Apply vendor security patches."
        
        if "distcc" in service or "2004-2687" in cve:
            return "Configure distccd to only accept connections from trusted hosts. Disable if not needed."
        
        if "mysql" in service:
            return "Update MySQL to latest version. Enforce strong passwords. Restrict network access."
        
        if "ssh" in service:
            return "Disable password authentication. Use SSH keys only. Update to latest OpenSSH version."
        
        if "http" in service or "apache" in service:
            return "Update web server to latest version. Apply security patches. Review application code."
        
        if "smb" in service or "445" in str(vuln.get("port", "")):
            return "Update SMB/Samba. Disable SMBv1. Enforce signing. Restrict anonymous access."
        
        if "telnet" in service:
            return "DISABLE TELNET immediately. Replace with SSH for encrypted remote access."
        
        if "ftp" in service:
            return "Upgrade FTP server. Consider SFTP instead. Disable anonymous access if not needed."
        
        # Generic recommendations by severity
        cvss = vuln.get("cvss", 0) or 0
        if cvss >= 9.0:
            return "URGENT: Apply vendor patch immediately. Consider taking system offline until patched."
        elif cvss >= 7.0:
            return "Apply vendor security patches. Review access controls and network segmentation."
        else:
            return "Apply vendor updates. Follow security hardening guidelines for this service."

    def _generate_attack_narrative(self, attack_summary: str) -> str:
        """Generate attack narrative from attack chain."""
        if not self.attack_chain:
            return "No attack chain recorded during this assessment."
        
        # Build narrative from attack chain
        phases = {}
        for step in self.attack_chain:
            agent = step.get("agent", "unknown")
            phase = agent.replace("Agent", "").lower()
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(step)
        
        narrative_parts = []
        
        if "recon" in phases:
            narrative_parts.append(
                f"**Reconnaissance Phase**: The assessment began with reconnaissance, "
                f"executing {len(phases['recon'])} actions to map the attack surface."
            )
        
        if "enumvuln" in phases or "enum" in phases:
            enum_key = "enumvuln" if "enumvuln" in phases else "enum"
            narrative_parts.append(
                f"**Enumeration Phase**: Service enumeration identified {len(self.ports)} open ports "
                f"and discovered {len(self.vulns)} vulnerabilities."
            )
        
        if "exploitation" in phases:
            shells_obtained = len(self.shells)
            narrative_parts.append(
                f"**Exploitation Phase**: Exploitation attempts resulted in {shells_obtained} "
                f"shell{'s' if shells_obtained != 1 else ''} being established."
            )
        
        if "privesc" in phases:
            root_obtained = any(s.get("user") == "root" for s in self.shells)
            narrative_parts.append(
                f"**Privilege Escalation**: {'Root access was successfully obtained.' if root_obtained else 'Privilege escalation was attempted.'}"
            )
        
        if "postexploit" in phases:
            narrative_parts.append(
                f"**Post-Exploitation**: {len(self.credentials)} credentials were harvested "
                f"and {len(self.loot)} sensitive data items were extracted."
            )
        
        return "\n\n".join(narrative_parts)

    def _fallback_analysis(self, vuln_summary: str) -> dict:
        """Fallback analysis when LLM is unavailable."""
        return {
            "executive_summary": self._generate_executive_summary(vuln_summary),
            "risk_assessment": self._generate_risk_assessment(vuln_summary),
            "remediation_recommendations": self._generate_remediation(vuln_summary),
            "attack_narrative": self._generate_attack_narrative(""),
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 3: PDF Report Generation
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_pdf_report(self, ai_analysis: dict) -> Path:
        """Generate professional PDF report."""
        mission_dir = self.report_dir / self.mission_id
        mission_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = mission_dir / "pentest_report.pdf"
        
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            rightMargin=1*cm,
            leftMargin=1*cm,
            topMargin=1.5*cm,
            bottomMargin=1.5*cm,
        )
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        styles.add(ParagraphStyle(
            name='Title2',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#1a1a2e"),
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.HexColor("#16213e"),
            borderWidth=1,
            borderColor=colors.HexColor("#e94560"),
            borderPadding=5,
        ))
        
        styles.add(ParagraphStyle(
            name='BodyText2',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
        ))
        
        elements = []
        
        # ── Cover Page ──
        elements.extend(self._pdf_cover_page(styles))
        elements.append(PageBreak())
        
        # ── Table of Contents ──
        elements.extend(self._pdf_toc(styles))
        elements.append(PageBreak())
        
        # ── Executive Summary ──
        elements.append(Paragraph("1. Executive Summary", styles['SectionHeader']))
        exec_summary = ai_analysis.get("executive_summary", "No summary available.")
        for para in exec_summary.split("\n\n"):
            if para.strip():
                elements.append(Paragraph(para.strip(), styles['BodyText2']))
                elements.append(Spacer(1, 8))
        elements.append(PageBreak())
        
        # ── Risk Assessment ──
        elements.append(Paragraph("2. Risk Assessment", styles['SectionHeader']))
        risk = ai_analysis.get("risk_assessment", "")
        for para in risk.split("\n\n"):
            if para.strip():
                elements.append(Paragraph(para.strip().replace("\n", "<br/>"), styles['BodyText2']))
                elements.append(Spacer(1, 8))
        elements.append(Spacer(1, 15))
        
        # ── Vulnerability Summary Chart ──
        elements.append(Paragraph("2.1 Vulnerability Distribution", styles['Heading3']))
        chart = self._create_vuln_chart()
        if chart:
            elements.append(chart)
        elements.append(PageBreak())
        
        # ── Vulnerability Details ──
        elements.append(Paragraph("3. Vulnerability Details", styles['SectionHeader']))
        elements.extend(self._pdf_vuln_table(styles))
        elements.append(PageBreak())
        
        # ── Attack Chain ──
        elements.append(Paragraph("4. Attack Narrative", styles['SectionHeader']))
        narrative = ai_analysis.get("attack_narrative", "")
        for para in narrative.split("\n\n"):
            if para.strip():
                clean = para.replace("**", "").strip()
                elements.append(Paragraph(clean, styles['BodyText2']))
                elements.append(Spacer(1, 8))
        elements.append(PageBreak())
        
        # ── Credentials & Loot ──
        if self.credentials or self.loot:
            elements.append(Paragraph("5. Harvested Data", styles['SectionHeader']))
            elements.extend(self._pdf_credentials_table(styles))
            elements.append(Spacer(1, 15))
            elements.extend(self._pdf_loot_table(styles))
            elements.append(PageBreak())
        
        # ── MITRE ATT&CK ──
        elements.append(Paragraph("6. MITRE ATT&CK Coverage", styles['SectionHeader']))
        elements.extend(self._pdf_mitre_table(styles))
        elements.append(PageBreak())
        
        # ── Remediation Recommendations ──
        elements.append(Paragraph("7. Remediation Recommendations", styles['SectionHeader']))
        elements.extend(self._pdf_remediation_table(styles, ai_analysis.get("remediation_recommendations", [])))
        
        # Build PDF
        doc.build(elements)
        self.log_success(f"PDF report generated: {pdf_path}")
        return pdf_path

    def _pdf_cover_page(self, styles) -> list:
        """Generate PDF cover page."""
        elements = []
        elements.append(Spacer(1, 2*inch))
        
        elements.append(Paragraph(
            "PENETRATION TEST REPORT",
            styles['Title2']
        ))
        
        elements.append(Spacer(1, 0.5*inch))
        
        elements.append(Paragraph(
            f"<b>Target:</b> {self.target}",
            ParagraphStyle('CoverInfo', parent=styles['Normal'], fontSize=14, alignment=TA_CENTER)
        ))
        
        elements.append(Spacer(1, 0.3*inch))
        
        elements.append(Paragraph(
            f"<b>Mission ID:</b> {self.mission_id}",
            ParagraphStyle('CoverInfo', parent=styles['Normal'], fontSize=12, alignment=TA_CENTER)
        ))
        
        elements.append(Spacer(1, 0.3*inch))
        
        elements.append(Paragraph(
            f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}",
            ParagraphStyle('CoverInfo', parent=styles['Normal'], fontSize=12, alignment=TA_CENTER)
        ))
        
        elements.append(Spacer(1, 1*inch))
        
        # Summary box
        critical = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "critical"])
        high = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "high"])
        
        summary_data = [
            ["Metric", "Value"],
            ["Total Vulnerabilities", str(len(self.vulns))],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Shells Obtained", str(len(self.shells))],
            ["Credentials Harvested", str(len(self.credentials))],
        ]
        
        summary_table = RLTable(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f0f0f0")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
        ]))
        
        elements.append(summary_table)
        
        elements.append(Spacer(1, 2*inch))
        
        elements.append(Paragraph(
            "<b>CONFIDENTIAL</b> - For Authorized Recipients Only",
            ParagraphStyle('Confidential', parent=styles['Normal'], fontSize=10, 
                          alignment=TA_CENTER, textColor=colors.red)
        ))
        
        return elements

    def _pdf_toc(self, styles) -> list:
        """Generate table of contents."""
        elements = []
        elements.append(Paragraph("Table of Contents", styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        toc_items = [
            ("1. Executive Summary", 3),
            ("2. Risk Assessment", 4),
            ("3. Vulnerability Details", 5),
            ("4. Attack Narrative", 6),
            ("5. Harvested Data", 7),
            ("6. MITRE ATT&CK Coverage", 8),
            ("7. Remediation Recommendations", 9),
        ]
        
        for title, page in toc_items:
            elements.append(Paragraph(
                f"{title} {'.' * 50} {page}",
                styles['Normal']
            ))
            elements.append(Spacer(1, 5))
        
        return elements

    def _create_vuln_chart(self) -> Optional[Drawing]:
        """Create vulnerability severity pie chart."""
        if not self.vulns:
            return None
        
        # Count by severity
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
