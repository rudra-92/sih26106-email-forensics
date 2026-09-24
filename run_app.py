"""One-click unified launcher for SandeshSetu (Frontend + Backend)."""

import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
DIST_DIR = FRONTEND_DIR / "dist"

def main():
    print("=" * 60)
    print("🛡️  SandeshSetu - Email Forensics & Attribution Platform")
    print("=" * 60)

    # Check if frontend build exists, build if missing
    if not DIST_DIR.is_dir():
        print("[*] Building frontend assets for unified experience...")
        try:
            subprocess.run(["npm", "run", "build"], cwd=str(FRONTEND_DIR), check=True, shell=True)
            print("[+] Frontend build completed.")
        except Exception as e:
            print(f"[!] Frontend build skipped/failed ({e}). Starting dev server mode.")

    port = int(os.environ.get("PORT", "8000"))
    url = f"http://127.0.0.1:{port}"
    print(f"[+] Starting SandeshSetu at {url}")
    print("[+] Opening browser...")

    def open_browser():
        time.sleep(1.5)
        webbrowser.open(url)

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=False)

if __name__ == "__main__":
    main()
