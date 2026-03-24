#!/usr/bin/env python3
import subprocess
import sys
import shutil
import os
import argparse
from pathlib import Path

def print_step(message):
    print(f"\n>> {message}")

def check_command(cmd, install_url):
    res = shutil.which(cmd)
    if res:
        print(f"✅ {cmd} found at {res}")
        return True
    else:
        print(f"❌ {cmd} not found. Please install it from {install_url}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Initialize the Release Server Development Environment.")
    parser.parse_args()

    print("Initializing Release Server Development Environment...")
    
    # 1. Prerequisite Checks
    print_step("Checking Prerequisites...")
    checks = [
        ("uv", "https://github.com/astral-sh/uv"),
        ("docker", "https://docs.docker.com/get-docker/"),
    ]
    
    missing = False
    for cmd, url in checks:
        if not check_command(cmd, url):
            missing = True

    # Check for act or gh act specifically
    act_url = "https://nektosact.com/installation/index.html"
    if shutil.which("act"):
        print(f"✅ act found at {shutil.which('act')}")
    elif shutil.which("gh"):
        # Try to check if 'gh act' is installed/working
        try:
            subprocess.run(["gh", "act", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print("✅ gh act found")
        except subprocess.CalledProcessError:
            print(f"❌ act or gh act not found. Please install act from {act_url}")
            missing = True
    else:
        print(f"❌ act or gh act not found. Please install act from {act_url}")
        missing = True
            
    if missing:
        print("\n⚠️  Some optional tools are missing. Basic setup will proceed, but full development capabilities may be limited.")
    
    # 2. Setup uv environment
    print_step("Setting up Python environment...")
    
    # Locate release-server directory relative to repo root
    # This script is at .github/skills/release-server-developer/scripts/
    # Repo root is 4 levels up
    script_dir = Path(__file__).resolve().parent
    # .github/skills/release-server-developer/scripts -> release-server-developer -> skills -> .github -> root
    repo_root = script_dir.parent.parent.parent.parent
    release_server_dir = repo_root / "release-server"
    
    if not release_server_dir.exists():
        # Fallback for when running in a different context structure
        # check if we are in repo root
        if Path("release-server").exists():
            release_server_dir = Path("release-server").resolve()
        else:
            print(f"❌ Error: release-server directory not found at {release_server_dir}")
            sys.exit(1)
        
    print(f"Working directory: {release_server_dir}")
    
    try:
        # Check if uv is installed first (redundant but safe)
        if shutil.which("uv"):
            print("Running: uv sync --all-extras")
            subprocess.run(["uv", "sync", "--all-extras"], cwd=release_server_dir, check=True)
            print("✅ Environment setup complete!")
        else:
            print("❌ uv is not installed. Cannot setup environment.")
            sys.exit(1)
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
