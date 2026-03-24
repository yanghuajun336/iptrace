#!/usr/bin/env python3
import re
import subprocess
import os
from pathlib import Path

def get_tool_help(script_path):
    """Executes the script with --help and returns the output."""
    try:
        # We use python3 explicitly to run the script
        result = subprocess.run(
            ["python3", str(script_path), "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            print(f"Error running {script_path}: {result.stderr}")
            return f"Error getting help: {result.stderr}"
        return result.stdout.strip()
    except Exception as e:
        print(f"Exception running {script_path}: {e}")
        return f"Error: {e}"

def update_skill_md(skill_md_path, scripts_dir):
    """Updates SKILL.md with tool usage."""
    content = skill_md_path.read_text(encoding="utf-8")
    
    # Regex to find tool markers: <!-- tool: name start --> ... <!-- tool: name end -->
    # We want to match existing blocks or placeholders
    pattern = re.compile(r"(<!-- tool: ([a-zA-Z0-9_-]+) start -->)(.*?)(<!-- tool: \2 end -->)", re.DOTALL)
    
    def replacement(match):
        start_tag = match.group(1)
        tool_name = match.group(2)
        end_tag = match.group(4)
        
        script_file = scripts_dir / f"{tool_name}.py"
        
        if not script_file.exists():
            print(f"Warning: Script {script_file} not found.")
            return match.group(0) # No change
            
        print(f"Updating usage for {tool_name}...")
        help_text = get_tool_help(script_file)
        
        new_content = f"\n\n```text\n{help_text}\n```\n\n"
        return f"{start_tag}{new_content}{end_tag}"

    new_content = pattern.sub(replacement, content)
    
    if content != new_content:
        skill_md_path.write_text(new_content, encoding="utf-8")
        print(f"Updated {skill_md_path}")
    else:
        print(f"No changes made to {skill_md_path}")

def main():
    current_dir = Path(__file__).parent.resolve()
    skill_md = current_dir.parent / "SKILL.md"
    scripts_dir = current_dir
    
    if not skill_md.exists():
        print(f"Error: {skill_md} not found.")
        return

    update_skill_md(skill_md, scripts_dir)

if __name__ == "__main__":
    main()
