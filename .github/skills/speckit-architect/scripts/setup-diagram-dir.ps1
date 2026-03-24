#!/usr/bin/env pwsh
# setup-diagram-dir.ps1 — Initialize a named diagram subdirectory inside a feature directory.
#
# This script is part of the speckit-architect skill and is self-contained.
#
# Usage:
#   ./setup-diagram-dir.ps1 -Subdir <name> [-FeatureDir <path>]
#   $env:FEATURE_DIR = '/path'; ./setup-diagram-dir.ps1 -Subdir <name>
#
# Parameters:
#   -Subdir       Name of the subdirectory to create (e.g. "uml", "c4") [required]
#   -FeatureDir   Feature directory path (param takes precedence over env var)
#
# Output:   absolute path to the created directory (stdout)
# Exit 0:   success (idempotent)
# Exit 1:   missing arguments or target is a regular file

[CmdletBinding()]
param(
    [string]$Subdir = "",
    [string]$FeatureDir = ""
)

$ErrorActionPreference = 'Stop'

if (-not $Subdir) {
    Write-Error "No subdirectory name specified. Pass -Subdir (e.g. uml, c4)."
    exit 1
}

if ($FeatureDir) {
    $targetDir = $FeatureDir
} elseif ($env:FEATURE_DIR) {
    $targetDir = $env:FEATURE_DIR
} else {
    Write-Error "No feature directory specified. Pass -FeatureDir or set FEATURE_DIR env var."
    exit 1
}

# Resolve to absolute path
$targetDir = (Resolve-Path $targetDir).Path

# Guard: targetDir must not be a regular file
if (Test-Path $targetDir -PathType Leaf) {
    Write-Error "FEATURE_DIR '$targetDir' is a regular file, not a directory."
    exit 1
}

# Create the subdirectory (idempotent)
$outDir = Join-Path $targetDir $Subdir
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# Output the absolute path
Write-Output $outDir
