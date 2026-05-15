"""AEGIS SOC — One-Command Launcher"""
import sys
import os

# Fix Windows console encoding for emojis
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn
from backend.config import settings

if __name__ == "__main__":
    print("AEGIS SOC -- Starting server...")
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level="info",
    )
