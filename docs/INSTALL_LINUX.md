# Installing and Running NetSentinel on Linux

---

## 1. Prerequisites
- **Ubuntu 20.04/22.04/24.04**, **Debian**, or **RHEL/CentOS/Fedora**
- **Python 3.10+**
- **Node.js 18+** & **npm**
- `iproute2` (for `ss`) and optionally `iptables` (for firewall mitigation)

Install system packages (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs npm iproute2
```

---

## 2. Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the backend:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

---

## 3. Frontend Setup
1. In another terminal, navigate to the frontend:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
2. Open `http://localhost:5173` in your browser.
