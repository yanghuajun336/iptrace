#!/usr/bin/env bash
# setup-diagram-dir.sh — Initialize a named diagram subdirectory inside a feature directory.
#
# This script is part of the speckit-architect skill and is self-contained.
#
# Usage:
#   setup-diagram-dir.sh <subdir> [FEATURE_DIR]
#   FEATURE_DIR=/path/to/feature setup-diagram-dir.sh <subdir>
#
# Arguments:
#   <subdir>      Name of the subdirectory to create (e.g. "uml", "c4")
#   [FEATURE_DIR] Feature directory path (positional $2 takes precedence over env var)
#
# Output:   absolute path to the created directory (stdout)
# Exit 0:   success (idempotent)
# Exit 1:   missing arguments or target is a regular file

set -e

SUBDIR="${1:-}"
if [[ -z "$SUBDIR" ]]; then
    echo "Error: No subdirectory name specified. Pass as first argument (e.g. uml, c4)." >&2
    exit 1
fi

if [[ -n "${2:-}" ]]; then
    TARGET_DIR="$2"
elif [[ -n "${FEATURE_DIR:-}" ]]; then
    TARGET_DIR="$FEATURE_DIR"
else
    echo "Error: No feature directory specified. Pass as \$2 or set FEATURE_DIR env var." >&2
    exit 1
fi

# Resolve to absolute path
TARGET_DIR="$(CDPATH="" cd "$TARGET_DIR" 2>/dev/null && pwd || echo "$TARGET_DIR")"

# Guard: TARGET_DIR must not be a regular file
if [[ -f "$TARGET_DIR" ]]; then
    echo "Error: FEATURE_DIR '$TARGET_DIR' is a regular file, not a directory." >&2
    exit 1
fi

# Create the subdirectory (idempotent)
OUT_DIR="$TARGET_DIR/$SUBDIR"
mkdir -p "$OUT_DIR"

# Output the absolute path
echo "$OUT_DIR"
