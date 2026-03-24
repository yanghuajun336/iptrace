#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests",
#     "rich",
# ]
# ///

import argparse
import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich import box

def main():
    parser = argparse.ArgumentParser(description="List packages on the Release Server")
    parser.add_argument("--url", default=os.environ.get("RELEASE_SERVER_URL", "http://localhost:8000"), help="Release Server URL")
    parser.add_argument("--token", default=os.environ.get("RELEASE_SERVER_TOKEN"), help="Auth token (if required)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    
    args = parser.parse_args()
    
    console = Console()
    
    headers = {"Accept": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
        
    try:
        response = requests.get(f"{args.url}/packages", headers=headers, timeout=10)
        response.raise_for_status()
        
        packages = response.json()
        
        if args.json:
            import json
            print(json.dumps(packages, indent=2))
            return

        if not packages:
            console.print("[yellow]No packages found.[/yellow]")
            return

        table = Table(title=f"Packages at {args.url}", box=box.ROUNDED)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Size", justify="right")
        table.add_column("Created", style="dim")
        table.add_column("SHA256", style="dim", no_wrap=True, overflow="ellipsis")
        
        for pkg in packages:
            name = pkg.get("name", "N/A")
            size = pkg.get("size", 0)
            created = pkg.get("created_at", "N/A")
            sha256 = pkg.get("sha256", "N/A")
            
            # Format size
            msg = f"{size} B"
            if size > 1024:
                msg = f"{size/1024:.1f} KB"
            if size > 1024*1024:
                msg = f"{size/(1024*1024):.1f} MB"
                
            table.add_row(name, msg, str(created), sha256)
            
        console.print(table)
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error connecting to server:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error processing response:[/bold red] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
