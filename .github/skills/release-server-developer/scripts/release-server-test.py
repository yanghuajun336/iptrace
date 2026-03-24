#!/usr/bin/env python3
import sys
import subprocess
import argparse
from pathlib import Path
import os

def main():
    parser = argparse.ArgumentParser(description="Run the release-server-publish workflow locally using 'gh act' via the wrapper script.")
    parser.add_argument("version", nargs="?", help="Optional version string to test (e.g., 0.0.90-localtest)")
    parser.add_argument("--event", "-e", default="push", choices=["push", "pull_request"], help="The event to trigger (default: push)")
    
    args = parser.parse_args()
    
    # Calculate paths
    script_path = Path(__file__).resolve()
    # Go up to repo root. 
    # scripts -> release-server-developer -> skills -> .github -> spec-kit
    repo_root = script_path.parents[4]
    
    script_to_run = repo_root / ".github" / "workflows" / "scripts" / "test-release-server.sh"
    
    if not script_to_run.exists():
        print(f"Error: Test script not found at {script_to_run}")
        sys.exit(1)
        
    cmd = [str(script_to_run)]
    
    if args.event:
        cmd.extend(["--event", args.event])
        
    if args.version:
        cmd.append(args.version)

    print(f"Executing: {' '.join(cmd)}")
    
    try:
        # Run the script and stream output
        # Using check=True to raise exception on non-zero exit code
        result = subprocess.run(cmd, check=True)
        sys.exit(result.returncode)
    except subprocess.CalledProcessError as e:
        print(f"Error executing test Script: {e}")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
