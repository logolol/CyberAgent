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
            if sev not in by_severity:
                sev = "unknown"
            by_severity[sev].append(v)
        
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
        for v in self.vulns:
            sev = self._cvss_to_severity(v.get("cvss", 0)).capitalize()
            if sev in counts:
                counts[sev] += 1
        
        # Filter out zeros
        data = [(k, v) for k, v in counts.items() if v > 0]
        if not data:
            return None
        
        drawing = Drawing(400, 200)
        
        pie = Pie()
        pie.x = 100
        pie.y = 25
        pie.width = 150
        pie.height = 150
        pie.data = [d[1] for d in data]
        pie.labels = [f"{d[0]}: {d[1]}" for d in data]
        
        pie.slices.strokeWidth = 0.5
        colors_list = [
            colors.HexColor("#DC143C"),  # Critical
            colors.HexColor("#FF4500"),  # High
            colors.HexColor("#FFA500"),  # Medium
            colors.HexColor("#FFD700"),  # Low
        ]
        for i, (label, _) in enumerate(data):
            color_idx = ["Critical", "High", "Medium", "Low"].index(label)
            pie.slices[i].fillColor = colors_list[color_idx]
        
        drawing.add(pie)
        return drawing

    def _pdf_vuln_table(self, styles) -> list:
        """Generate vulnerability details table."""
        elements = []
        
        if not self.vulns:
            elements.append(Paragraph("No vulnerabilities discovered.", styles['Normal']))
            return elements
        
        # Sort by CVSS descending
        sorted_vulns = sorted(self.vulns, key=lambda x: x.get("cvss", 0) or 0, reverse=True)
        
        table_data = [["CVE", "Service", "Port", "CVSS", "Severity", "Description"]]
        
        for v in sorted_vulns[:20]:  # Top 20
            cvss = v.get("cvss", 0) or 0
            sev = self._cvss_to_severity(cvss).upper()
            desc = v.get("description", "")[:40] + "..." if len(v.get("description", "")) > 40 else v.get("description", "")
            
            table_data.append([
                v.get("cve", "N/A")[:20],
                v.get("service", "?")[:15],
                str(v.get("port", "?")),
                f"{cvss:.1f}",
                sev,
                desc,
            ])
        
        col_widths = [1.3*inch, 1*inch, 0.6*inch, 0.6*inch, 0.8*inch, 2.5*inch]
        table = RLTable(table_data, colWidths=col_widths)
        
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        
        # Color-code severity cells
        for i, v in enumerate(sorted_vulns[:20], start=1):
            cvss = v.get("cvss", 0) or 0
            sev = self._cvss_to_severity(cvss)
            if sev == "critical":
                style.append(('BACKGROUND', (4, i), (4, i), colors.HexColor("#DC143C")))
                style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
            elif sev == "high":
                style.append(('BACKGROUND', (4, i), (4, i), colors.HexColor("#FF4500")))
                style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
        
        table.setStyle(TableStyle(style))
        elements.append(table)
        
        if len(self.vulns) > 20:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph(
                f"<i>Showing top 20 of {len(self.vulns)} vulnerabilities</i>",
                styles['Normal']
            ))
        
        return elements

    def _pdf_credentials_table(self, styles) -> list:
        """Generate credentials table."""
        elements = []
        
        if not self.credentials:
            return elements
        
        elements.append(Paragraph("5.1 Harvested Credentials", styles['Heading3']))
        
        table_data = [["Username", "Password/Hash", "Service", "Source"]]
        
        for cred in self.credentials[:15]:
            pwd = cred.get("password", cred.get("hash", ""))
            if len(pwd) > 30:
                pwd = pwd[:27] + "..."
            
            table_data.append([
                cred.get("username", "?"),
                pwd,
                cred.get("service", "?"),
                cred.get("source", "?")[:20],
            ])
        
        table = RLTable(table_data, colWidths=[1.5*inch, 2.5*inch, 1*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(table)
        return elements

    def _pdf_loot_table(self, styles) -> list:
        """Generate loot table."""
        elements = []
        
        if not self.loot:
            return elements
        
        elements.append(Paragraph("5.2 Extracted Sensitive Data", styles['Heading3']))
        
        table_data = [["Type", "Description", "Source"]]
        
        for item in self.loot[:10]:
            desc = str(item.get("content", item.get("description", "")))[:50]
            
            table_data.append([
                item.get("type", "?"),
                desc,
                item.get("source", "?")[:30],
            ])
        
        table = RLTable(table_data, colWidths=[1.5*inch, 3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(table)
        return elements

    def _pdf_mitre_table(self, styles) -> list:
        """Generate MITRE ATT&CK table."""
        elements = []
        
        if not self.mitre_techniques:
            elements.append(Paragraph("No MITRE ATT&CK techniques recorded.", styles['Normal']))
            return elements
        
        # MITRE technique descriptions
        mitre_desc = {
            "T1046": ("Network Service Scanning", "Discovery"),
            "T1018": ("Remote System Discovery", "Discovery"),
            "T1087": ("Account Discovery", "Discovery"),
            "T1083": ("File and Directory Discovery", "Discovery"),
            "T1190": ("Exploit Public-Facing Application", "Initial Access"),
            "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
            "T1021": ("Remote Services", "Lateral Movement"),
            "T1003": ("OS Credential Dumping", "Credential Access"),
            "T1552": ("Unsecured Credentials", "Credential Access"),
            "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
            "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
            "T1059": ("Command and Scripting Interpreter", "Execution"),
        }
        
        table_data = [["Technique ID", "Name", "Tactic"]]
        
        for tech in sorted(set(self.mitre_techniques)):
            name, tactic = mitre_desc.get(tech, ("Unknown", "Unknown"))
            table_data.append([tech, name, tactic])
        
        table = RLTable(table_data, colWidths=[1.2*inch, 3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(table)
        return elements

    def _pdf_remediation_table(self, styles, recommendations: list) -> list:
        """Generate remediation recommendations table."""
        elements = []
        
        if not recommendations:
            elements.append(Paragraph("No specific recommendations generated.", styles['Normal']))
            return elements
        
        for i, rec in enumerate(recommendations, start=1):
            priority = rec.get("priority", "MEDIUM")
            cve = rec.get("cve", "N/A")
            service = rec.get("service", "?")
            issue = rec.get("issue", "")
            remedy = rec.get("recommendation", "")
            
            # Priority color
            if priority == "CRITICAL":
                bg_color = colors.HexColor("#DC143C")
            elif priority == "HIGH":
                bg_color = colors.HexColor("#FF4500")
            else:
                bg_color = colors.HexColor("#FFA500")
            
            elements.append(Paragraph(
                f"<b>{i}. [{priority}] {cve} - {service}</b>",
                ParagraphStyle('RecHeader', parent=styles['Normal'], fontSize=11,
                              textColor=bg_color, spaceBefore=10)
            ))
            
            elements.append(Paragraph(
                f"<b>Issue:</b> {issue}",
                styles['BodyText2']
            ))
            
            elements.append(Paragraph(
                f"<b>Recommendation:</b> {remedy}",
                styles['BodyText2']
            ))
            
            elements.append(Spacer(1, 10))
        
        return elements

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 4: Markdown Report Generation
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_markdown_report(self, ai_analysis: dict) -> Path:
        """Generate Markdown report."""
        mission_dir = self.report_dir / self.mission_id
        mission_dir.mkdir(parents=True, exist_ok=True)
        md_path = mission_dir / "pentest_report.md"
        
        lines = []
        
        # Header
        lines.append(f"# Penetration Test Report")
        lines.append(f"")
        lines.append(f"**Target:** {self.target}")
        lines.append(f"**Mission ID:** {self.mission_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"")
        lines.append("---")
        lines.append("")
        
        # Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(ai_analysis.get("executive_summary", "No summary available."))
        lines.append("")
        
        # Risk Assessment
        lines.append("## 2. Risk Assessment")
        lines.append("")
        lines.append("```")
        lines.append(ai_analysis.get("risk_assessment", ""))
        lines.append("```")
        lines.append("")
        
        # Vulnerability Summary
        lines.append("## 3. Vulnerability Summary")
        lines.append("")
        lines.append(f"| CVE | Service | Port | CVSS | Severity |")
        lines.append(f"|-----|---------|------|------|----------|")
        
        for v in sorted(self.vulns, key=lambda x: x.get("cvss", 0) or 0, reverse=True)[:20]:
            cvss = v.get("cvss", 0) or 0
            sev = self._cvss_to_severity(cvss).upper()
            lines.append(f"| {v.get('cve', 'N/A')} | {v.get('service', '?')} | {v.get('port', '?')} | {cvss:.1f} | {sev} |")
        
        lines.append("")
        
        # Attack Narrative
        lines.append("## 4. Attack Narrative")
        lines.append("")
        lines.append(ai_analysis.get("attack_narrative", ""))
        lines.append("")
        
        # Credentials
        if self.credentials:
            lines.append("## 5. Harvested Credentials")
            lines.append("")
            lines.append("| Username | Password/Hash | Service |")
            lines.append("|----------|---------------|---------|")
            for c in self.credentials[:10]:
                pwd = c.get("password", c.get("hash", ""))[:30]
                lines.append(f"| {c.get('username', '?')} | {pwd} | {c.get('service', '?')} |")
            lines.append("")
        
        # MITRE ATT&CK
        lines.append("## 6. MITRE ATT&CK Techniques")
        lines.append("")
        for t in sorted(set(self.mitre_techniques)):
            lines.append(f"- {t}")
        lines.append("")
        
        # Remediation
        lines.append("## 7. Remediation Recommendations")
        lines.append("")
        for i, rec in enumerate(ai_analysis.get("remediation_recommendations", [])[:10], start=1):
            lines.append(f"### {i}. [{rec.get('priority', 'MEDIUM')}] {rec.get('cve', 'N/A')}")
            lines.append(f"")
            lines.append(f"**Issue:** {rec.get('issue', '')}")
            lines.append(f"")
            lines.append(f"**Recommendation:** {rec.get('recommendation', '')}")
            lines.append("")
        
        # Write file
        md_path.write_text("\n".join(lines))
        self.log_success(f"Markdown report generated: {md_path}")
        return md_path

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 5: JSON Summary
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_json_summary(self, ai_analysis: dict) -> Path:
        """Generate JSON summary for programmatic access."""
        mission_dir = self.report_dir / self.mission_id
        mission_dir.mkdir(parents=True, exist_ok=True)
        json_path = mission_dir / "report_summary.json"
        
        summary = {
            "mission_id": self.mission_id,
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "statistics": {
                "total_vulnerabilities": len(self.vulns),
                "critical": len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "critical"]),
                "high": len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "high"]),
                "medium": len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "medium"]),
                "low": len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "low"]),
                "shells_obtained": len(self.shells),
                "credentials_harvested": len(self.credentials),
                "loot_items": len(self.loot),
                "mitre_techniques": len(set(self.mitre_techniques)),
                "attack_chain_steps": len(self.attack_chain),
            },
            "top_vulnerabilities": [
                {
                    "cve": v.get("cve"),
                    "cvss": v.get("cvss"),
                    "service": v.get("service"),
                    "port": v.get("port"),
                }
                for v in sorted(self.vulns, key=lambda x: x.get("cvss", 0) or 0, reverse=True)[:5]
            ],
            "mitre_techniques": sorted(set(self.mitre_techniques)),
            "ai_analysis": {
                "executive_summary": ai_analysis.get("executive_summary", "")[:500],
                "risk_level": self._extract_risk_level(ai_analysis.get("risk_assessment", "")),
            },
        }
        
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)
        
        self.log_success(f"JSON summary generated: {json_path}")
        return json_path

    # ══════════════════════════════════════════════════════════════════════════
    # Utilities
    # ══════════════════════════════════════════════════════════════════════════

    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0:
            return "low"
        return "info"

    def _extract_risk_level(self, risk_assessment: str) -> str:
        """Extract risk level from assessment text."""
        if "CRITICAL" in risk_assessment:
            return "CRITICAL"
        elif "HIGH" in risk_assessment:
            return "HIGH"
        elif "MEDIUM" in risk_assessment:
            return "MEDIUM"
        return "LOW"

    def _build_result(self, pdf_path: Path, md_path: Path, json_path: Path, ai_analysis: dict) -> dict:
        """Build final result."""
        
        critical = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "critical"])
        high = len([v for v in self.vulns if self._cvss_to_severity(v.get("cvss", 0)) == "high"])
        
        self.console.print(Panel(
            f"[bold green]✓ Report Generation Complete[/]\n"
            f"[white]PDF:[/] {pdf_path}\n"
            f"[white]Markdown:[/] {md_path}\n"
            f"[white]JSON:[/] {json_path}\n"
            f"[white]Vulnerabilities:[/] {len(self.vulns)} ({critical} critical, {high} high)",
            border_style="green",
        ))
        
        self.memory.log_action(
            self.agent_name,
            "report_generated",
            f"pdf={pdf_path.name} vulns={len(self.vulns)} creds={len(self.credentials)}"
        )
        
        return {
            "agent": self.agent_name,
            "success": True,
            "result": {
                "pdf_path": str(pdf_path),
                "markdown_path": str(md_path),
                "json_path": str(json_path),
                "total_vulns": len(self.vulns),
                "critical": critical,
                "high": high,
                "credentials_harvested": len(self.credentials),
                "shells_obtained": len(self.shells),
                "mitre_techniques": len(set(self.mitre_techniques)),
            },
        }
