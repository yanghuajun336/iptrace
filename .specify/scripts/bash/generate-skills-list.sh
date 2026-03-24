#!/usr/bin/env bash
set -euo pipefail

# scripts/bash/generate-skills-list.sh
# Generates an XML list of available skills and injects them into a template.

PATHS=()
OUTPUT_FILE=""
TEMPLATE_FILE=".specify/templates/instructions/speckit-skills.instructions.md"
FORCE=false

usage() {
  echo "Usage: $0 -p <path> [-p <path>] [-o <output_file>] [-t <template_file>] [-f]"
  echo
  echo "Options:"
  echo "  -p, --path      Path to a directory containing skills (can be used multiple times)"
  echo "  -o, --output    Output file path"
  echo "  -t, --template  Template file path (default: $TEMPLATE_FILE)"
  echo "  -f, --force     Overwrite output file if it exists"
  echo "  -h, --help      Show this help message"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--path)
      PATHS+=("$2")
      shift 2 ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2 ;;
    -t|--template)
      TEMPLATE_FILE="$2"
      shift 2 ;;
    -f|--force)
      FORCE=true
      shift ;;
    -h|--help)
      usage ;;
    *)
      echo "Error: Unknown option $1" >&2
      exit 1 ;;
  esac
done

if [[ ${#PATHS[@]} -eq 0 ]]; then
  echo "Error: At least one path (-p) is required" >&2
  exit 1
fi

if [[ -n "$OUTPUT_FILE" ]]; then
  OUT_DIR=$(dirname "$OUTPUT_FILE")
  if [[ ! -d "$OUT_DIR" ]]; then
    echo "Error: Output directory '$OUT_DIR' does not exist" >&2
    exit 1
  fi
  if [[ ! -w "$OUT_DIR" ]]; then
    echo "Error: Cannot write to output directory '$OUT_DIR'" >&2
    exit 1
  fi
  if [[ -f "$OUTPUT_FILE" ]] && [[ ! -w "$OUTPUT_FILE" ]]; then
    echo "Error: Cannot write to output file '$OUTPUT_FILE'" >&2
    exit 1
  fi
  
  if [[ -f "$OUTPUT_FILE" ]] && [[ "$FORCE" = false ]]; then
    echo "Error: Output file '$OUTPUT_FILE' already exists. Use -f to overwrite." >&2
    exit 1
  fi
fi

generate_xml() {
  echo "<available_skills>"
  for dir in "${PATHS[@]}"; do
    if [[ ! -d "$dir" ]]; then
      echo "Warning: Path '$dir' is not a directory. Skipping." >&2
      continue
    fi
    if [[ ! -r "$dir" ]]; then
      echo "Error: Cannot read directory '$dir'" >&2
      exit 1
    fi

    # Find all SKILL.md files recursively
    find "$dir" -name "SKILL.md" | while read -r skill_file; do
      # Extract frontmatter using awk
      name=$(awk '
        /^---$/ { if (++dash == 2) exit }
        dash == 1 && /^name:/ { sub(/^name:[[:space:]]*/, ""); print }
      ' "$skill_file")
      
      description=$(awk '
        /^---$/ { if (++dash == 2) exit }
        dash == 1 && /^description:/ { sub(/^description:[[:space:]]*/, ""); print }
      ' "$skill_file")

      if [[ -n "$name" && -n "$description" ]]; then
        # Use location relative to workspace root (assuming script runs from root)
        normalized_path=$(echo "$skill_file" | sed 's|^./||')
        echo "  <skill>"
        echo "    <name>$name</name>"
        echo "    <description>$description</description>"
        echo "    <location>\${workspaceFolder}/$normalized_path</location>"
        echo "  </skill>"
      fi
    done
  done
  echo "</available_skills>"
}

XML_CONTENT=$(generate_xml)

if [[ -f "$TEMPLATE_FILE" ]]; then
  # Inject XML_CONTENT into TEMPLATE_FILE at {SKILLS_LIST}
  FINAL_CONTENT=$(awk -v list="$XML_CONTENT" '{
    if ($0 ~ /\{SKILLS_LIST\}/) {
      gsub(/\{SKILLS_LIST\}/, list)
    }
    print
  }' "$TEMPLATE_FILE")
else
  echo "Warning: Template file '$TEMPLATE_FILE' not found. Outputting raw XML." >&2
  FINAL_CONTENT="$XML_CONTENT"
fi

if [[ -n "$OUTPUT_FILE" ]]; then
  echo "$FINAL_CONTENT" > "$OUTPUT_FILE"
  echo "Generated skills list saved to $OUTPUT_FILE"
else
  echo "$FINAL_CONTENT"
fi
