# Project Brief: Multi-Agent PentestAI & Mitigation Platform

## Overview
The Multi-Agent PentestAI and Mitigation Platform is an autonomous system built on CrewAI / LangChain that acts as a human expert. It performs end-to-end penetration testing from a single domain name input and provides automated mitigations subject to Admin-in-the-Loop approval.

**Company:** ComunikCRM | **Duration:** 22 weeks (Phase 1: 18w, Phase 2: 4w) | **PFE Graduation Project**

## 💻 Hardware (Attacker Machine)
- **OS:** Parrot Security 7.1 (echo) — Debian-based, pre-installed offensive tools
- **CPU:** Intel Core i5-13500H — 12 cores / 16 threads, up to 4.7GHz, VT-x enabled
- **RAM:** 23GB total (~17GB available) — No GPU dedicated (Intel Iris Xe integrated only)
- **Storage:** Samsung NVMe SSD (PM9B1, DRAM-less)
- **Network:** WiFi (wlo1: 192.168.100.8), USB-Ethernet (enp0s20f0u1: 10.225.245.226)
- **VMware:** Installed — vmnet1 (192.168.80.1/24 Host-Only), vmnet8 (172.16.215.1/24 NAT)
- **No dedicated GPU** → LLM inference must use CPU-optimized quantized models (Q4)

## 🎯 Core Requirements & Integrations
- **Company Context:** ComunikCRM (Linux infra: VoIP/SIP Asterisk, Apache/PHP, MySQL/MongoDB, DNS, SMTP, REST APIs)
- **Attacker OS:** Parrot OS (local machine) — NO external API calls, all data stays local
- **Target OS:** Linux Infrastructure (dynamic — no hardcoded service assumptions)
- **Agent Framework:** CrewAI (primary) / LangChain (fallback), Python 3.11+
- **LLM Runtime:** Ollama local inference — Qwen2.5:8B (default) / DeepSeek-R1:8B (deep reasoning)
- **Embedding Model:** nomic-embed-text (via Ollama) for ChromaDB RAG
- **Memory/Knowledge Base:** ChromaDB (vector semantic) + JSON state (persistent) + SQLite logs
- **Knowledge Sources:** Exploit-DB RAG, MITRE ATT&CK JSON (local), NVD/CVE feeds, GTFOBins, PayloadsAllTheThings
- **Infrastructure Automation:** Ansible (Phase 2 only — pentest dispatch + mitigation deployment)
- **MCP Integration:** Free MCP (Model Context Protocol) servers for Pentest tool access and context operations
- **Notification:** Python smtplib SMTP for admin confirmation emails

## 🏛️ Architecture
### ReAct Paradigm (ALL agents follow this loop)
- **Thought** → LLM reasons about current state + prior observations → plans next action
- **Action** → calls tool (nmap, Metasploit, SQLMap...) or delegates to sub-agent
- **Observation** → output parsed, structured, stored in ChromaDB → fed into next reasoning cycle

### Phase 1: Multi-Agent Attack Chain (18 weeks)
Orchestrator receives domain name → drives 7 specialized agents sequentially → context via ChromaDB + JSON

| # | Agent | Key Tools | Output |
|---|-------|-----------|--------|
| 0 | **Orchestrator** | CrewAI Manager LLM / LangChain AgentExecutor | Mission control, state management |
| 1 | **Recon Agent** | subfinder, amass, dnsrecon, dnsenum, theHarvester, WhatWeb, Whois, nmap | Host list, open ports, banners |
| 2 | **Enumeration Agent** | nmap NSE, SIPVicious (svmap/svwar), gobuster, ffuf, banner grabbing | Service versions, endpoints, tech stack |
| 3 | **Vuln Scan Agent** | Searchsploit, Nikto, CVE/Exploit-DB RAG, CVSS scoring | Ranked vuln list with exploitability scores |
| 4 | **Exploitation Agent** | Hydra, Metasploit, SQLMap, wfuzz, SIPVicious, swaks, smtp-user-enum, paramiko | Shell access, confirmed exploits |
| 5 | **PrivEsc Agent** | LinPEAS, GTFOBins (RAG), Exploit-DB RAG, kernel CVE search | Root/elevated shell, PrivEsc path |
| 6 | **Post-Exploit Agent** | /etc/shadow, .bash_history, config files extraction, pivot discovery | Credential dump, internal hosts |
| 7 | **Reporting Agent** | CVSS scoring, MITRE ATT&CK JSON mapping, PDF/terminal report | Full pentest report |

### Exploitation Vectors (dynamic, adapted to discovered services)
- SSH/Linux services: Hydra, Metasploit, paramiko — brute force, auth bypass (CVE)
- Web/PHP/APIs: SQLMap, wfuzz, Metasploit web — SQLi, LFI, RCE, file upload bypass
- VoIP/SIP: SIPVicious, Metasploit SIP — registration attacks, eavesdrop
- SMTP/Mail: swaks, smtp-user-enum — user enum, open relay, spoofing
- Databases: SQLMap, nmap NSE DB — unauthenticated access, credential dump
- DNS: dnsrecon, fierce — zone transfer, cache poisoning
- Any other: Searchsploit + RAG → CVE-matched exploit from Exploit-DB

### Phase 2: Ansible Integration & Remediation (4 weeks)
1. Infra Engineer enters domain → Dashboard → clicks Launch Pentest
2. Ansible Tower → `launch_pentest.yml` → PentestAI Docker container on Parrot OS
3. Full attack chain runs autonomously (6–24 hours max)
4. Reporting Agent → JSON report (critical findings + prioritized mitigation list)
5. Ansible Tower → Report to Dashboard → Admin notification
6. Admin reviews → approves/rejects each mitigation action (Human-in-the-Loop)
7. Ansible Tower → `deploy_mitigation.yml` → Mitigation Agent deployed to victim machine
8. Mitigation Agent executes ONLY approved actions (no autonomous decision authority)
9. Mitigation Agent → confirmation notification + execution logs → Dashboard

**Mitigation Agent (Phase 2 only):** patches, closes ports, hardens configs, disables services — ONLY what admin explicitly approved.

## 🗂️ Technical Stack
| Category | Technology |
|----------|------------|
| Language | Python 3.11+ |
| Agent Framework | CrewAI (primary) / LangChain (fallback) |
| LLM Runtime | Ollama + Qwen2.5:8B / DeepSeek-R1:8B |
| Embedding | nomic-embed-text (Ollama) |
| Vector Memory | ChromaDB |
| State Persistence | JSON files + SQLite |
| Parallelism | Python threading / asyncio |
| Infra Automation | Ansible (Phase 2) |
| Notification | Python smtplib |
| MITRE Mapping | MITRE ATT&CK JSON (local) |
| MCP | Free MCP servers for pentest tool integration |

## 📅 Development Schedule
| Weeks | Phase | Key Deliverable |
|-------|-------|----------------|
| S1-S2 | Foundations | Env setup, Ollama+ChromaDB+CrewAI, RAG ingestion |
| S3-S4 | Orchestrator | Orchestrator Agent + ReAct engine + JSON state |
| S5-S6 | Recon | Recon Agent (parallel threads: DNS, OSINT, active) |
| S7-S8 | Enum+VulnScan | Enumeration + VulnScan Agents validated |
| S9-S11 | Exploitation | Exploitation Agent (parallel vectors + chaining) |
| S12-S13 | PrivEsc+Post | PrivEsc (LinPEAS, GTFOBins) + Post-Exploit |
| S14-S15 | Reporting | Reporting Agent Phase 1 (CVSS + MITRE ATT&CK) |
| S16-S17 | Phase 1 Test | Full run on Metasploitable2 + ComunikCRM test server |
| S18 | Phase 1 Wrap | Benchmarks + performance tuning + docs |
| S19-S20 | Phase 2 Ansible | Ansible playbooks + Mitigation Agent |
| S21 | Phase 2 Test | End-to-end Phase 2 test |
| S22 | Final Defense | PFE Report + Defense + live demo |

## 📊 KPIs
- Full pentest on Metasploitable2: **< 6 hours**
- Vulnerability detection rate: **>= 85%**
- False positive rate: **<= 10%**
- CVSS + MITRE ATT&CK report auto-generated: **100%**
- Mitigations successfully applied after approval: **>= 80%**

## ⚠️ Critical Constraints
- **No UI in Phase 1** — terminal only
- **No external API calls** — all LLM inference is local via Ollama
- **No data leaves the machine** — strict air-gap for LLM
- **Mitigation Agent** — ONLY executes explicitly approved actions, zero autonomous decision authority
- **Dynamic target** — no hardcoded service assumptions, platform adapts to whatever is running
- **Legal** — written authorization from ComunikCRM mandatory before Phase 1B and Phase 2
- **CPU-only inference** — use Q4 quantized models (no dedicated GPU)

## 🧪 Test Environments
- **Phase 1A:** Metasploitable2 VM (VMware, isolated network) — full chain validation
- **Phase 1B:** ComunikCRM test server (real services, non-destructive, authorized scope)
- **Phase 2:** ComunikCRM real infrastructure via Ansible (domain name only as input)

## 🚀 Goals and Deliverables
1. PentestAI Platform source code (S22)
2. Metasploitable2 pentest report (S17)
3. ComunikCRM test server pentest report (S18)
4. Ansible Phase 2 playbooks (S20)
5. Technical documentation (S22)
6. PFE thesis report (S22)
7. Final defense presentation + live demo (S22)
