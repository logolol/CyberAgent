# Project Brief: Multi-Agent PentestAI & Mitigation Platform

## Overview
The Multi-Agent PentestAI and Mitigation Platform is an autonomous system built on CrewAI / LangChain that acts as a human expert. It performs end-to-end penetration testing from a single domain name input and provides automated mitigations subject to Admin-in-the-Loop approval.

## 🎯 Core Requirements & Integrations
- **Company Context:** ComunikCRM
- **Attacker OS:** Parrot OS (local machine)
- **Target OS:** Linux Infrastructure
- **Agent Framework:** CrewAI / LangChain (Python 3.11+)
- **LLM Runtime:** Ollama local inference (Qwen2.5:8B / DeepSeek-R1:8B)
- **Memory/Knowledge Base:** ChromaDB + JSON state + Exploit-DB RAG, MITRE ATT&CK, GTFOBins
- **Infrastructure Automation:** Ansible (Phase 2)
- **New Integration Required:** Integrate MCP (Model Context Protocol) for Pentest context and operations.

## 🏛️ Architecture
### Phase 1: Attack Chain
The orchestrator drives specialized ReAct agents systematically transferring context via ChromaDB & JSON.
1. **Recon Agent:** DNS, OSINT, port scanning.
2. **Enumeration Agent:** Deep service fingerprinting, gobuster, nmap NSE.
3. **Vuln Scan Agent:** CVE matching, CVSS scoring, Nikto, Searchsploit.
4. **Exploitation Agent:** Vector-specific parallel threads (Web, Service, Credentials).
5. **Privilege Escalation Agent:** Kernel exploits, SUID/Sudo abuse (GTFOBins).
6. **Post-Exploit Agent:** Looting, credentials, pivoting.
7. **Reporting Agent:** Full detailed report generation for Phase 1.

### Phase 2: Mitigation Pipeline
- **Ansible Tower Integration:** Handles dispatch of pentest container.
- **Admin Dashboard / Human-in-the-loop:** The engineer receives the report, reviews mitigations, and approves them.
- **Mitigation Agent:** Executed via Ansible exclusively with approved remediation actions on the victim machine.

## 🚀 Goals and Deliverables
- 18 Weeks (Phase 1): Fully validate the entire multi-agent loop on Metasploitable2 and ComunikCRM test servers.
- 4 Weeks (Phase 2): Fully pipeline with Ansible, Dashboard approval, and automatic mitigation.
- Strict constraint: NO graphical UI for Phase 1 (terminal only), NO data leaves the local LLM environment, Mitigations ONLY execute upon explicit admin approval.
