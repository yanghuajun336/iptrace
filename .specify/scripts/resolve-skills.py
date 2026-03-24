#!/usr/bin/env python3
import os
import sys
import glob

SCRIPT_VERSION = "2.0.0"
DEFAULT_SKILL_DIRS = ["skills", ".specify/skills", ".github/skills", ".claude/skills"]

def get_skill_dirs(repo_root):
    """Read .speckit.yaml for custom skill dirs; fall back to defaults."""
    config_path = os.path.join(repo_root, ".speckit.yaml")
    if not os.path.isfile(config_path):
        return [os.path.join(repo_root, d) for d in DEFAULT_SKILL_DIRS]

    try:
        config = None
        try:
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except ImportError:
            config = _parse_config(config_path)

        if config:
            # Version soft warning
            cfg_version = str(config.get('version', ''))
            if cfg_version and cfg_version.split('.')[0] != SCRIPT_VERSION.split('.')[0]:
                sys.stderr.write(
                    f"Warning: .speckit.yaml version {cfg_version} may be incompatible "
                    f"with resolve-skills.py {SCRIPT_VERSION}\n"
                )

            # Skill dirs override
            skills_cfg = config.get('skills', {})
            if isinstance(skills_cfg, dict):
                scan_dirs = skills_cfg.get('scan_dirs', [])
                if scan_dirs and isinstance(scan_dirs, list):
                    return [os.path.join(repo_root, d) for d in scan_dirs]

    except Exception as e:
        sys.stderr.write(f"Warning: Error reading .speckit.yaml: {e}\n")

    return [os.path.join(repo_root, d) for d in DEFAULT_SKILL_DIRS]


def _parse_config(config_path):
    """Minimal parser for .speckit.yaml (version + skills.scan_dirs only)."""
    config = {}
    try:
        with open(config_path, 'r') as f:
            lines = f.readlines()

        in_skills = False
        in_scan_dirs = False
        scan_dirs = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                continue

            if stripped.startswith('version:'):
                val = stripped.split(':', 1)[1].strip().strip('"').strip("'")
                config['version'] = val
                in_skills = False
                in_scan_dirs = False
            elif stripped == 'skills:':
                in_skills = True
                in_scan_dirs = False
            elif in_skills and stripped == 'scan_dirs:':
                in_scan_dirs = True
            elif in_scan_dirs and stripped.startswith('- '):
                scan_dirs.append(stripped[2:].strip())
            elif not line[0].isspace() and stripped:
                in_skills = False
                in_scan_dirs = False

        if scan_dirs:
            config['skills'] = {'scan_dirs': scan_dirs}

    except Exception:
        pass
    return config


def list_domain_skills(repo_root):
    """List skills that have SKILL.md but NO speckit-adapter.yaml (domain/user skills)."""
    skill_dirs = get_skill_dirs(repo_root)
    results = []
    seen_names = set()

    for skills_dir in skill_dirs:
        if not os.path.isdir(skills_dir):
            continue
        for entry in sorted(os.listdir(skills_dir)):
            skill_path = os.path.join(skills_dir, entry)
            if not os.path.isdir(skill_path):
                continue
            skill_md = os.path.join(skill_path, "SKILL.md")
            adapter = os.path.join(skill_path, "speckit-adapter.yaml")
            if os.path.isfile(skill_md) and not os.path.isfile(adapter):
                name, description = _parse_skill_md(skill_md, entry)
                if name not in seen_names:
                    seen_names.add(name)
                    results.append({"name": name, "description": description})

    return results


def _parse_skill_md(skill_md_path, fallback_name):
    """Extract name and description from SKILL.md frontmatter.
    Handles inline values, quoted strings, and YAML block scalars (>, >-, |, |-).
    """
    name = fallback_name
    description = ""
    try:
        with open(skill_md_path, 'r') as f:
            lines = f.readlines()

        if not lines or lines[0].strip() != '---':
            return name, description

        # Find end of frontmatter
        fm_end = None
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '---':
                fm_end = i
                break
        if fm_end is None:
            return name, description

        fm_lines = lines[1:fm_end]
        i = 0
        while i < len(fm_lines):
            line = fm_lines[i]
            stripped = line.strip()

            if stripped.startswith('name:'):
                val = stripped.split(':', 1)[1].strip().strip('"').strip("'")
                if val:
                    name = val
            elif stripped.startswith('description:'):
                val = stripped.split(':', 1)[1].strip()
                if val in ('>', '>-', '|', '|-'):
                    # Block scalar: collect subsequent indented lines
                    block_lines = []
                    i += 1
                    while i < len(fm_lines):
                        next_line = fm_lines[i]
                        if next_line and not next_line[0].isspace():
                            break
                        content = next_line.strip()
                        if content:
                            block_lines.append(content)
                        i += 1
                    # For folded (>) join with space; for literal (|) join with space too (first line)
                    description = ' '.join(block_lines) if block_lines else ""
                    continue
                else:
                    description = val.strip('"').strip("'")
            i += 1

        # Fallback: first non-empty, non-header body line
        if not description:
            for line in lines[fm_end + 1:]:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    description = stripped
                    break
    except Exception:
        pass
    return name, description


def main():
    if len(sys.argv) < 2:
        print("Usage: resolve-skills.py <phase> [repo_root]")
        print("       resolve-skills.py --list-domain [repo_root]")
        sys.exit(1)

    phase = sys.argv[1]
    repo_root = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()

    # --list-domain: output non-adapter (domain/user) skills for specify-phase discovery
    if phase == "--list-domain":
        skills = list_domain_skills(repo_root)
        if skills:
            for skill in skills:
                desc = skill['description'] or "(no description)"
                print(f"- **{skill['name']}**: {desc}")
        else:
            print("_No domain skills found in configured scan directories._")
        return

    skill_dirs = get_skill_dirs(repo_root)

    # Find all adapter files across all skill directories
    adapter_files = []
    for skills_dir in skill_dirs:
        if os.path.isdir(skills_dir):
            adapter_files.extend(glob.glob(os.path.join(skills_dir, "*", "speckit-adapter.yaml")))
    
    matched_skills = []

    for adapter_file in adapter_files:
        try:
            with open(adapter_file, 'r') as f:
                content = f.read()
                data = None
                
                # Try yaml if available
                try:
                    import yaml
                    data = yaml.safe_load(content)
                except ImportError:
                    pass
                
                # Fallback to manual
                if data is None:
                    data = manual_parse(content)
                
                if not data or 'hooks' not in data:
                    continue
                    
                for hook in data['hooks']:
                    if hook.get('phase') == phase:
                        skill_dir = os.path.dirname(adapter_file)
                        context_file = hook.get('context')
                        priority = hook.get('priority', 0)
                        instructions = hook.get('instructions', '')
                        
                        if context_file:
                            full_path = os.path.join(skill_dir, context_file)
                            if os.path.exists(full_path):
                                skill_name = data.get('name', 'Unknown')
                                _, description = _parse_skill_md(full_path, skill_name)
                                matched_skills.append({
                                    'priority': priority,
                                    'path': full_path,
                                    'name': skill_name,
                                    'description': description,
                                    'instructions': instructions
                                })
        except Exception as e:
            sys.stderr.write(f"Error processing {adapter_file}: {e}\n")

    # Sort by priority desc
    matched_skills.sort(key=lambda x: x['priority'], reverse=True)

    if matched_skills:
        print(f'<active_skills phase="{phase}" count="{len(matched_skills)}">')
        print(f'  <directive>The following specialist skills are active for this phase. You MUST read each skill\'s persona_file and fully adopt its persona and workflows before proceeding.</directive>')
        
        for skill in matched_skills:
            name = skill['name']
            description = skill.get('description', '')
            print(f'\n  <skill name="{name}">')
            if description:
                print(f'    <description>{description}</description>')
            print(f'    <persona_file>{skill["path"]}</persona_file>')
            if skill.get('instructions'):
                print('    <integration>')
                print(skill['instructions'].strip())
                print('    </integration>')
            print(f'  </skill>')
        
        print('\n</active_skills>')
    else:
        print(f'<active_skills phase="{phase}" count="0">')
        print(f'  <directive>No specialist skills are configured for this phase. Proceed with general best practices.</directive>')
        print('</active_skills>')

def manual_parse(text):
    # Basic parser for adapter YAML format with multi-line instructions support
    import re
    data = {
        'hooks': [],
        'name': 'Unknown'
    }
    current_hook = {}
    
    lines = text.split('\n')
    name_match = re.search(r'^name:\s*(.+)', text, re.MULTILINE)
    if name_match:
        data['name'] = name_match.group(1).strip()
        
    in_hooks = False
    in_instructions = False
    instructions_indent = 0
    instructions_lines = []
    
    for line in lines:
        stripped = line.strip()
        
        # Handle multi-line instructions block
        if in_instructions:
            # Detect indentation level of instruction content
            if line and not line[0].isspace():
                # Top-level key — end instructions
                current_hook['instructions'] = '\n'.join(instructions_lines)
                in_instructions = False
                instructions_lines = []
            elif stripped.startswith('- phase:'):
                # New hook entry — end instructions
                current_hook['instructions'] = '\n'.join(instructions_lines)
                in_instructions = False
                instructions_lines = []
            elif stripped == '' and not instructions_lines:
                continue
            else:
                # Calculate content indent (strip the block indent)
                raw = line.rstrip()
                if instructions_indent == 0 and raw.strip():
                    instructions_indent = len(raw) - len(raw.lstrip())
                if instructions_indent > 0 and len(raw) >= instructions_indent:
                    instructions_lines.append(raw[instructions_indent:])
                else:
                    instructions_lines.append(raw.strip())
                continue
        
        if stripped.startswith('hooks:'):
            in_hooks = True
            continue
        
        if in_hooks:
            if stripped.startswith('- phase:'):
                if current_hook:
                    data['hooks'].append(current_hook)
                current_hook = {'phase': stripped.split(':', 1)[1].strip()}
            elif stripped.startswith('priority:'):
                current_hook['priority'] = int(stripped.split(':', 1)[1].strip())
            elif stripped.startswith('context:'):
                current_hook['context'] = stripped.split(':', 1)[1].strip()
            elif stripped.startswith('instructions:'):
                value = stripped.split(':', 1)[1].strip()
                if value == '|' or value == '>':
                    in_instructions = True
                    instructions_indent = 0
                    instructions_lines = []
                else:
                    current_hook['instructions'] = value
            elif stripped == '' or (not line.startswith(' ') and not line.startswith('-')):
                if current_hook:
                    data['hooks'].append(current_hook)
                    current_hook = {}
                if stripped != '' and not line.startswith(' '):
                    in_hooks = False
    
    # Flush any remaining state
    if in_instructions and instructions_lines:
        current_hook['instructions'] = '\n'.join(instructions_lines)
    if current_hook:
        data['hooks'].append(current_hook)
        
    return data

if __name__ == "__main__":
    main()
