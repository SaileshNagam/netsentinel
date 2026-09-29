# Academic Project Report: NetSentinel
## Agentic Network Security Monitoring, Threat Detection, and Defensive Response for Windows and Linux

**Author:** Sailesh Nagam  
**Degree:** Bachelor of Technology in Computer Science & Engineering (Cyber Security)  
**Project Category:** Defensive Cyber Security & Explainable AI Systems  

---

## Abstract
Modern enterprise and campus environments encounter sophisticated cyber threats ranging from stealthy command-and-control (C2) beaconing to unauthorized lateral movement and brute-force credential stuffing. Conventional Security Information and Event Management (SIEM) systems frequently overwhelm human analysts with unprioritized alert volumes, while rigid automated Endpoint Detection and Response (EDR) agents pose stability risks due to autonomous, unverified destructive actions.

This project introduces **NetSentinel**, an agentic defensive cybersecurity platform engineered to monitor network and host telemetry across Windows and Linux environments. NetSentinel bridges real-time socket tracking with running process context, executes deterministic multi-rule detection, employs an explainable 6-stage autonomous agentic reasoning pipeline (Observe $\rightarrow$ Analyze $\rightarrow$ Investigate $\rightarrow$ Decide $\rightarrow$ Respond $\rightarrow$ Report), and enforces a human-in-the-loop Safety Gate before executing controlled defensive mitigations (such as host firewall IP blocking and process isolation).

---

## 1. Introduction & Motivation
Host security monitoring requires cross-layer correlation: network connections alone lack process attribution, while process monitoring alone lacks network awareness. By unifying socket-to-process telemetry through OS-native instrumentation and combining it with deterministic detection and structured agentic analysis, NetSentinel provides practical and explainable threat management tailored for resource-constrained, local deployment.

---

## 2. System Architecture
NetSentinel is organized into modular layers:
1. **Host Telemetry Collection Layer:** Uses `psutil`, Linux `/var/log` & `ss`, and Windows PowerShell `Get-WinEvent` to continuously capture active sockets, CPU/RAM footprints, and authentication logs.
2. **Deterministic Detection Engine:** 6 transparent detection rules covering unusual outbound ports, non-network processes initiating sockets, rapid port scans, brute-force logins, periodic beaconing (analyzed via coefficient of variation), and test IP destination access.
3. **Agentic Cognitive Engine:** Structured reasoning loop providing explainable factor breakdowns rather than black-box machine learning classifications.
4. **Safety Gate & Defensive Response:** Protects system availability by verifying approvals, guarding system PIDs, and sanitizing targets against injection before simulating or executing OS-level defenses.
5. **Modern SOC Interface:** React 18 / TypeScript frontend presenting interactive topology maps, live socket grids, and a defense approval dashboard.

---

## 3. Results & Evaluation
- **Detection Precision:** Successfully isolates simulated C2 beacons at regular intervals ($CV \le 0.25$), horizontal port scans ($\ge 10$ distinct ports hit), and failed login bursts.
- **Safety Gate Reliability:** 100% of invalid addresses, system PIDs, and unauthorized AI self-approvals were trapped and rejected by automated unit testing.
- **Test Coverage:** 66 automated tests covering unit, integration, and scenario simulation suites.
- **Resource Footprint:** Operates locally on consumer hardware without external cloud or proprietary GPU dependencies.

---

## 4. Conclusion & Future Work
NetSentinel demonstrates that explainable agentic cybersecurity and safe human-in-the-loop automation can be effectively deployed on standard laptop infrastructure. Future enhancements include extending honeypot trap ports and integrating local offline LLM fine-tunes for multilingual incident narrative generation.
