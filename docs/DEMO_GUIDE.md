# NetSentinel Live Demo Guide
## Safe Demonstration of Detection & Agentic Response

This guide provides step-by-step instructions for demonstrating NetSentinel during project evaluations without harming network infrastructure or generating malicious traffic.

---

## 1. Starting the Platform

### Terminal 1: Backend
```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Terminal 2: Frontend
```bash
cd frontend
npm run dev
```
Open your browser to: `http://localhost:5173`

---

## 2. Walkthrough Scenarios

### Scenario 1: Live Telemetry & Process Binding
1. Switch to the **CONNECTIONS** view in the top navigation bar.
2. Demonstrate how local sockets are bound to active system processes and PIDs.
3. Open a browser and navigate to a website; show the new TCP connections appearing in real-time.

### Scenario 2: Safe C2-Like Beacon Simulation
1. Toggle the dashboard to **DEMO LAB** mode using the top banner.
2. Click the **TEST C2 BEACON** button.
3. Observe:
   - Detection Engine flags `RULE_E_BEACONING` and `RULE_F_UNUSUAL_DESTINATION`.
   - The Agentic pipeline executes the 6 stages in real-time.
   - A new incident is generated with an explainable factor breakdown.
   - A pending defensive action appears in the **DEFENSES** queue.

### Scenario 3: Human-in-the-Loop Mitigation
1. Click the **DEFENSES** tab.
2. Review the pending action: `BLOCK_IP` targeting `198.51.100.50`.
3. Click **SIMULATE** to execute a dry run. Show that the action was safely modeled and audited without modifying production firewall rules.
4. Point out the SHA-256 tamper-evident audit hash generated in the database.
