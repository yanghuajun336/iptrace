#!/usr/bin/env python3
import sys
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Delete a package from the Release Server.")
    parser.add_argument("filename", help="Name of the file/package to delete")
    parser.add_argument("--url", "-u", help="Server URL")
    parser.add_argument("--token", "-t", help="Auth Token")
    
    args = parser.parse_args()
    
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[4]
    
    script_to_run = repo_root / "release-server" / "scripts" / "delete.sh"
    
    if not script_to_run.exists():
        print(f"Error: Delete script not found at {script_to_run}")
        sys.exit(1)
    
    cmd = ["bash", str(script_to_run)]
    
    if args.url:
        cmd.extend(["--url", args.url])
    if args.token:
        cmd.extend(["--token", args.token])
        
    cmd.append(args.filename)
    
    print(f"Executing: {' '.join(cmd)}")
    
    cwd = repo_root / "release-server"
    
    try:
        subprocess.run(cmd, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
