# NetSentinel Architecture Specification
## Agentic Network Security & Defensive Response Platform for Windows and Linux

---

## 1. System Overview

NetSentinel is a cross-platform defensive cybersecurity platform designed for local network monitoring, process-to-network telemetry binding, threat detection, autonomous agentic reasoning, and human-in-the-loop defensive response.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          REACT SOC DASHBOARD                           │
│  [Asset Inventory]  [Topology Map]  [Live Connections]  [Defenses]    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / WebSocket (:8000)
┌───────────────────────────────────▼────────────────────────────────────┐
│                        FASTAPI BACKEND RUNTIME                         │
│                                                                        │
│  ┌──────────────────────┐              ┌───────────────────────────┐  │
│  │ Cross-Platform       │              │ Threat Detection Engine   │  │
│  │ Telemetry Collector  │              │ (Rules A through F)       │  │
│  │ (psutil / ss / EVTX) │─────────────►│ Explainable Risk Scoring  │  │
│  └──────────────────────┘              └─────────────┬─────────────┘  │
│                                                      │                 │
│  ┌──────────────────────┐              ┌─────────────▼─────────────┐  │
│  │ Safety Gate Enforcer │              │ NetSentinel Security Agent│  │
│  │ (Protected IPs/PIDs, │◄─────────────│ 6-Stage Reasoning Chain   │  │
│  │ Human Approval Req.) │              │ Observe→Analyze→...Report │  │
│  └──────────┬───────────┘              └───────────────────────────┘  │
│             │                                                          │
│  ┌──────────▼───────────┐              ┌───────────────────────────┐  │
│  │ Defensive Response   │              │ SQLite + WAL Engine       │  │
│  │ (iptables / netsh /  │              │ Time-Series Telemetry &   │  │
│  │ psutil termination)  │              │ Cryptographic Audit Logs  │  │
│  └──────────────────────┘              └───────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Cross-Platform Telemetry Collectors
- **`app.monitoring.common_monitor`**: Cross-platform network socket extraction via `psutil`, normalizing IP/port pairs, TCP/UDP protocols, connection states, and binding sockets to process PIDs and executable paths.
- **`app.monitoring.linux_monitor`**: Fast socket interrogation using `ss -tunpH` and Linux authentication log parsing (`/var/log/auth.log`, `/var/log/secure`).
- **`app.monitoring.windows_monitor`**: PowerShell and `Get-WinEvent` bindings for Windows Event IDs (4624 login, 4625 failed login, 4672 admin logon, 4688 process creation) and Windows Defender Firewall profile management.

### 2.2 Threat Detection Engine (`app.detection.rule_engine`)
Operates deterministically using evidence-based heuristics:
- **Rule A (Unusual Outbound Port)**: Flags non-standard egress channels (e.g. 4444, 5555, 6667, 31337).
- **Rule B (Suspicious Process-to-Network)**: Flags binaries that have no benign reason to open external sockets (e.g. `notepad.exe`, `calc.exe`).
- **Rule C (Port Scanning)**: Sliding-window detection of rapid distinct port contacts from single sources.
- **Rule D (Brute-Force Detection)**: Thresholded analysis of repeated failed authentication events.
- **Rule E (C2-Like Periodic Beaconing)**: Statistical timestamp analysis calculating interval means and coefficient of variation ($CV \le 0.25$) to identify automated heartbeat telemetry.
- **Rule F (Unusual Destination)**: Flags connections to RFC 5737 test ranges or unassigned IP blocks.

### 2.3 Agentic Security Reasoning (`app.agents.security_agent`)
Follows a rigorous 6-stage cognitive loop:
1. **OBSERVE**: Correlates incoming telemetry and trigger alerts.
2. **ANALYZE**: Breaks down risk contributions and rule metrics.
3. **INVESTIGATE**: Gathers process lineage, user identity, and historical connection patterns.
4. **DECIDE**: Formulates structured recommendations (e.g. `TEMPORARY_BLOCK`, `ALERT_OPERATOR`).
5. **RESPOND**: Prepares action specifications and sets status to `PENDING_APPROVAL`.
6. **REPORT**: Generates human-readable incident dossiers with full audit trails.

### 2.4 Safety Gate Enforcer (`app.response.safety_gate`)
Non-negotiable security layer guaranteeing that AI recommendations cannot destabilize the host:
- Disallows autonomous approval by `SYSTEM` or `AI`.
- Rejects targets containing shell metacharacters.
- Protects loopback (`127.0.0.1`), broadcast, and link-local ranges from being blocked.
- Protects system/kernel PIDs ($\le 10$) and NetSentinel's own PID from termination.
- Requires explicit SOC operator authorization.

### 2.5 Storage Architecture
- Powered by `SQLite 3` with `aiosqlite` in `WAL` (Write-Ahead Logging) mode.
- Stores historical connections, process inventories, normalized security events, incidents, and tamper-evident SHA-256 audit logs.
