# Installing and Running NetSentinel on Windows

---

## 1. Prerequisites
- **Windows 10 / 11** or **Windows Server 2019/2022**
- **Python 3.11+** installed (check "Add Python to PATH" during installation)
- **Node.js 18+** installed
- **PowerShell 5.1+** (included by default in modern Windows)
- Run PowerShell as **Administrator** for host socket and firewall inspection.

---

## 2. Backend Setup
1. Open PowerShell and navigate to the project root:
   ```powershell
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
4. Start the backend:
   ```powershell
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

---

## 3. Frontend Setup
1. In a second terminal, navigate to the frontend:
   ```powershell
   cd frontend
   npm install
   npm run dev
   ```
2. Access the SOC dashboard at `http://localhost:5173`.
