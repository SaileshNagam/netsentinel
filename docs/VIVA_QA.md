# NetSentinel Viva Voce: Questions & Answers
## Final Year Project Examination & Technical Defense Reference

---

### Q1: What is the core problem NetSentinel solves?
**A:** NetSentinel addresses the gap between raw network monitoring and host-level process attribution. Traditional network monitors see packets but do not know which PID generated them. NetSentinel correlates network sockets with local process IDs, usernames, and executable paths, applying an explainable agentic investigation workflow to guide SOC analysts without risky autonomous actions.

---

### Q2: What makes the system "Agentic"?
**A:** Unlike static SIEM alert rule engines, NetSentinel's Security Agent implements an iterative 6-stage cognitive loop:
1. **Observe:** Ingests alerts and cross-references them against active telemetry.
2. **Analyze:** Calculates additive factor breakdowns and severity weights.
3. **Investigate:** Gathers process parentage, user privileges, and historical connection patterns.
4. **Decide:** Weighs evidence to produce a contextual defense recommendation.
5. **Respond:** Stages proposed mitigations for operator evaluation.
6. **Report:** Synthesizes an end-to-end incident narrative for compliance and review.

---

### Q3: Why is autonomous execution disabled by default?
**A:** In cybersecurity and industrial operations, autonomous destructive actions (such as blocking a critical management gateway or terminating a database service) risk causing severe Denial of Service (Self-DoS). NetSentinel enforces a mandatory **Safety Gate** where disruptive actions require human operator sign-off, and simulation/dry-run mode is enabled by default.

---

### Q4: How does NetSentinel detect periodic C2 beaconing?
**A:** By grouping historical connections by destination `(remote_ip, remote_port, process)` and analyzing the inter-connection arrival times. If the coefficient of variation ($CV = \frac{\sigma}{\mu}$) is $\le 0.25$, it indicates mechanical, automated scheduling rather than human browsing behavior.

---

### Q5: How is cross-platform compatibility achieved between Windows and Linux?
**A:** NetSentinel utilizes platform-neutral abstractions via Python's `psutil` for socket-to-process binding, combined with platform-specific adapters:
- On **Linux**, it inspects `/var/log/auth.log` or `/var/log/secure` and executes `iptables` rules.
- On **Windows**, it interfaces with PowerShell `Get-WinEvent` for Security Event Logs (4624, 4625, 4688) and uses `netsh advfirewall` for firewall rules.
- If executed on other systems (e.g. macOS), it falls back safely to simulation mode without crashing.

---

### Q6: How does NetSentinel protect against command injection in defense actions?
**A:** The `SafetyGate` module rejects any target containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, etc.), strictly validates IP addresses using Python's `ipaddress` library, and executes OS commands using argument vectors rather than shell execution (`shell=False`).
