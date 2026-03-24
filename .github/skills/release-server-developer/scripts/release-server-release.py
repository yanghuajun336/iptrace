#!/usr/bin/env python3
import sys
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Package and release the Release Server application.")
    parser.add_argument("version", nargs="?", help="Version to release (optional, defaults to pyproject.toml version)")
    
    args = parser.parse_args()
    
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[4]
    
    script_to_run = repo_root / "release-server" / "scripts" / "release.sh"
    
    if not script_to_run.exists():
        print(f"Error: Release script not found at {script_to_run}")
        sys.exit(1)
    
    cmd = ["bash", str(script_to_run)]
    
    if args.version:
        cmd.append(args.version)
    
    print(f"Executing: {' '.join(cmd)}")
    
    cwd = repo_root / "release-server"
    
    try:
        subprocess.run(cmd, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
