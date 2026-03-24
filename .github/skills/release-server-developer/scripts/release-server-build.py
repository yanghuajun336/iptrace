#!/usr/bin/env python3
import sys
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Build the Release Server Docker image.")
    parser.add_argument("--registry", help="Container registry (default: ghcr.io)")
    parser.add_argument("--author", help="Image author/namespace (default: zlink-cloudtech)")
    parser.add_argument("--image-name", help="Image name (default: speckit-rs)")
    parser.add_argument("--tag", help="Image tag (default: latest)")
    
    args = parser.parse_args()
    
    # Calculate paths
    # .github/skills/release-server-developer/scripts/release-server-build.py
    # -> root is 5 args up from file path if strictly strictly structure
    # But usually we find root by looking for pyproject.toml or .git
    
    script_path = Path(__file__).resolve()
    # Go up to repo root. 
    # scripts -> release-server-developer -> skills -> .github -> spec-kit
    repo_root = script_path.parents[4]
    
    script_to_run = repo_root / "release-server" / "scripts" / "build.sh"
    
    if not script_to_run.exists():
        print(f"Error: Build script not found at {script_to_run}")
        sys.exit(1)
        
    # Prepare environment variables
    env = None
    if any([args.registry, args.author, args.image_name, args.tag]):
        import os
        env = os.environ.copy()
        if args.registry:
            env["REGISTRY"] = args.registry
        if args.author:
            env["AUTHOR"] = args.author
        if args.image_name:
            env["IMAGE_NAME"] = args.image_name
        if args.tag:
            env["TAG"] = args.tag

    print(f"Executing: {script_to_run}")
    
    # Ensure working directory is set correctly (release-server folder)
    # The build script expects to be run where?
    # build.sh says: "docker build -t ... ."
    # So it must be run from release-server directory.
    cwd = repo_root / "release-server"
    
    try:
        subprocess.run(["bash", str(script_to_run)], check=True, cwd=cwd, env=env)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
