Deployment Guide: ZenJournalThis guide covers how to run ZenJournal on your local machine (development) and how to self-host it on a Linux server/Raspberry Pi (production).1. Quick Start (Local Development)This is the easiest way to run the app on your laptop.PrerequisitesPython 3.9+Node.js 16+ (Check with node -v and python --version)StepsDownload & Extract:Copy the install_zen_journal.py script to a new folder and run it:python install_zen_journal.py
Start Backend (Terminal 1):cd backend
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
Start Frontend (Terminal 2):cd frontend
npm install
npm run dev
Access: Open http://localhost:5173 in your browser.2. Self-Hosting (Production on Linux)These instructions assume you are using a Debian-based system (Ubuntu, Raspberry Pi OS).Step A: Build the FrontendWe need to turn the React code into static HTML/JS files so we don't need to run a separate Node server in production.Inside frontend/:npm run build
This creates a dist folder. Move this folder to your backend directory or keep note of its path (e.g., /home/pi/zenjournal/frontend/dist).Step B: Configure Backend to Serve Frontend(Optional but recommended for simple hosting)You can modify backend/server.py to serve the static files.Add this to server.py:from fastapi.staticfiles import StaticFiles

# ... existing imports ...

app = FastAPI(title="ZenJournal API")

# ... existing middleware ...

# IMPORTANT: Mount this AFTER your API routes, or use a specific path
# However, for a simple root mount:
app.mount("/", StaticFiles(directory="../frontend/dist", html=True), name="static")
Note: You may need to install aiofiles via pip: pip install aiofilesStep C: Run with Systemd (Keep it alive)Don't use uvicorn --reload in production. Use a system service.Create service file:sudo nano /etc/systemd/system/zenjournal.servicePaste content:[Unit]
Description=ZenJournal Service
After=network.target

[Service]
User=pi  # CHANGE THIS to your username
WorkingDirectory=/home/pi/zenjournal/backend # CHANGE THIS
ExecStart=/usr/bin/python3 -m uvicorn server:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
Start it:sudo systemctl enable zenjournal
sudo systemctl start zenjournal
Step D: Accessing itIf you are on your home Wi-Fi, you can now access the app via your server's IP:http://192.168.1.X:80003. Database ManagementThe database is a single file: backend/zenjournal.db.Backup: Simply copy this file to a safe location (e.g., Google Drive, USB stick) periodically.Restore: Paste the backup file back into the backend/ folder.
