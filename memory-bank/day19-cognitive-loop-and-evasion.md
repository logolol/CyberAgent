# Day 19 — Autonomous Cognitive Loop & Evasion Integration

## Overview
Day 19 represents a fundamental shift in CyberAgent's architecture from a linear, deterministic state machine to a **closed-loop cognitive agent**. This transformation was driven by the need to handle adversarial environments (firewalls, IDS) and provide actionable, production-ready remediation.

## 1. Cognitive "Plan → Execute → Verify → Reflect" Loop
We implemented a new orchestrator pattern that treats each phase as a decision point rather than a fixed script.

- **Post-Phase Critic**: After each phase (Recon, Enum, etc.), the Orchestrator now invokes a "Critic" loop. This critic compares the current findings against the mission objectives. If the findings are insufficient, the Orchestrator can decide to re-run the phase with different parameters or backtrack to a previous phase.
- **Uncertainty Tracking**: Every node in the attack graph now carries a `confidence_score` (0.0-1.0). High-uncertainty findings trigger automatic re-verification or deeper enumeration.
- **Resource Budgeting**: Implemented dynamic time and token budgets. If an agent is stuck in a loop (e.g., hallucinating nmap args), the budgeter terminates the action and forces a deterministic fallback.

## 2. Firewall Evasion & Adversarial Hardening
To handle external targets and cloud hosts (OVH, etc.), we integrated `FirewallDetectionAgent` as a mandatory Phase 0.

- **Evasion Profiles**: Based on TTL analysis, RST packet behavior, and timing analysis, the agent assigns an evasion profile:
  - `light`: `-T3` timing, standard flags.
  - `medium`: `-T2` timing, `-f` (fragmentation), decoy IPs.
  - `heavy`: `-T1` timing, `-f -f`, custom MTU, random data length.
- **Dynamic Injection**: `EnumVulnAgent` and `ReconAgent` now retrieve this profile from `MissionMemory` and dynamically inject the flags into their tool calls.
- **Bug Fix (Target Hallucination)**: Fixed a critical bug where the LLM would hallucinate target strings like `"IP"` or `"<target_ip>"` when building nmap commands. We added a filter to `_resolve_spec` that forces these back to the validated target IP.

## 3. Mitigation Agent (Ansible YAML)
The user requested that the remediation system be "aware of what's going on" and provide "real mitigation" in YAML format.

- **Ansible Integration**: Shifted from fragile `.sh` scripts to idempotent Ansible Playbooks (`.yml`).
- **Playbook Design**:
  - Uses `apt` for package updates.
  - Uses `service` for state-aware restarts.
  - Uses `lineinfile` for config hardening (e.g., disabling SMBv1, hardening SSH).
  - Uses `ufw` for firewall rule management.
- **Context Awareness**: The `MitigationAgent` pulls the exact service versions and CVEs from `MissionMemory` to generate specific, targeted tasks rather than generic advice.

## 4. Performance & Reliability
- **UCB1 Exploit Selection**: Upgraded `ExperienceMemory` to use the Upper Confidence Bound (UCB1) algorithm. This balances "exploitation" (using known-good exploits) with "exploration" (trying new CVEs that might work better).
- **RAG-Adaptive Wordlists**: For web directory brute-forcing, the agent now queries the knowledge base for service-specific paths (e.g., "Apache default paths", "WordPress hidden files") and generates a custom temp wordlist for `gobuster`.

## 5. Summary of Key Files
- `src/agents/orchestrator_agent.py`: New attack chain with firewall phase and critic loop.
- `src/agents/firewall_agent.py`: Logic for profile detection and flag generation.
- `src/agents/enum_vuln_agent.py`: Nmap evasion injection and target filtering.
- `src/agents/mitigation_agent.py`: Ansible YAML playbook generation logic.
- `src/memory/mission_memory.py`: Enhanced state tracking for evasion and confidence.

## Next Steps
- [ ] Implement `LateralMovementAgent` for pivoting.
- [ ] Add `CloudSecurityAgent` for AWS/GCP specific misconfigurations.
- [ ] Enhance the report generator to include visual attack path diagrams.
