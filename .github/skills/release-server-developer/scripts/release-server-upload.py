#!/usr/bin/env python3
import sys
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Upload a package to the Release Server.")
    parser.add_argument("file_path", help="Path to the file to upload")
    parser.add_argument("--url", "-u", help="Server URL")
    parser.add_argument("--token", "-t", help="Auth Token")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing file")
    
    args = parser.parse_args()
    
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[4]
    
    script_to_run = repo_root / "release-server" / "scripts" / "upload.sh"
    
    if not script_to_run.exists():
        print(f"Error: Upload script not found at {script_to_run}")
        sys.exit(1)
    
    cmd = ["bash", str(script_to_run)]
    
    if args.url:
        cmd.extend(["--url", args.url])
    if args.token:
        cmd.extend(["--token", args.token])
    if args.force:
        cmd.append("--force")
        
    # Add file path (convert to absolute if needed, or pass as is)
    cmd.append(args.file_path)
    
    print(f"Executing: {' '.join(cmd)}")
    
    cwd = repo_root / "release-server"
    
    try:
        subprocess.run(cmd, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
