#!/usr/bin/env python3
import sys
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Run the Release Server locally.")
    parser.add_argument("--port", default="8000", help="Port to run on (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--reload", action="store_true", default=True, help="Enable auto-reload (default: True)")
    
    args = parser.parse_args()
    
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[4]
    
    cwd = repo_root / "release-server"
    
    # Check if uv is installed
    try:
        subprocess.run(["uv", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        has_uv = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        has_uv = False
        print("Warning: 'uv' not found. Falling back to direct python/uvicorn execution if possible.")

    if has_uv:
        cmd = ["uv", "run", "uvicorn", "release_server.server:app"]
    else:
        cmd = ["python3", "-m", "uvicorn", "release_server.server:app"]

    cmd.extend(["--host", args.host])
    cmd.extend(["--port", args.port])
    
    if args.reload:
        cmd.append("--reload")
        
    print(f"Executing: {' '.join(cmd)}")
    print(f"Working Directory: {cwd}")
    
    try:
        subprocess.run(cmd, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
