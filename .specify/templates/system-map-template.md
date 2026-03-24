# System Map

**Purpose**: Centralized index of all authoritative documentation for the project. Enables AI agents to quickly locate relevant context without scanning the entire codebase.

**Template Version**: 2.0.0
**Version**: [SYSTEM_MAP_VERSION] | **Created**: [CREATION_DATE] | **Last Updated**: [DATE]
**Maintained By**: [Team/Owner]
**Review Frequency**: After each major feature completion

---

## Project Identity

**Project**: [PROJECT_NAME]
**Description**: [PROJECT_DESCRIPTION]

### Core Principles

<!-- Populated from constitution. List key principles as numbered items. -->

### Technology Stack

<!-- List the primary languages, frameworks, and tools used in this project. -->

| Category | Technology | Purpose |
|----------|-----------|---------|

### Project Components

<!-- List the major components/modules of this project. -->

| Component | Location | Technology | Purpose |
|-----------|----------|------------|---------|

---

## Essential Artifacts

<!--
Status values: ✅ Active | ⚠️ Missing | 🗑️ Deprecated
Fill tables based on your project type. Not all categories apply to every project.

Common artifacts by project type:
- Web Backend: System Architecture, Database Schema, API Design, Deployment Config
- CLI Tool: Command Structure, Plugin Architecture, Distribution Config
- Frontend App: Component Hierarchy, State Management, Routing Map
- Library/SDK: Public API Reference, Compatibility Matrix, Usage Examples
- Microservices: Service Topology, Contract Catalog, Inter-service Auth
- Data Pipeline: Data Flow Diagram, Schema Registry, Processing SLAs

Add rows that are relevant; remove or leave empty categories that don't apply.
-->

### 🏛️ Architecture & Design

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|

### 📐 Configuration & Infrastructure

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|

### 🧪 Quality & Testing

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|

### 🧭 Project Memory

<!--
  These entries anchor the Gap Analysis in /speckit.plan.
  Always keep status up to date so agents do not incorrectly create bootstrap tasks
  for files that already exist on disk.
-->

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|
| System Map | `.specify/memory/system-map.md` | ✅ Active | [DATE] | Living index of all project components and documentation |
| Project Constitution | `.specify/memory/constitution.md` | ✅ Active | [DATE] | Governing principles and architectural constraints |

### 📚 Decisions & Standards

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|

---

## Integration Points

### External Services

<!-- List third-party services, APIs, or platforms the project depends on. Leave empty if none. -->

| Service | Type | Documentation | Purpose |
|---------|------|---------------|---------|

### Internal Dependencies

<!-- List internal modules or services that this project depends on or exposes. Leave empty if not applicable. -->

| Module | Location | Interface | Description |
|--------|----------|-----------|-------------|

---

## Knowledge Sources

### Documentation

<!-- List user-facing and developer-facing documentation. -->

| Topic | Location | Type | Description |
|-------|----------|------|-------------|

### Technical Context

<!-- List domain-specific resources, guides, or references relevant to this project. -->

| Domain | Resource | Description |
|--------|----------|-------------|

---

## Using the System Map

### For Planning (`/speckit.plan`)

1. **Identify Touched Components**: Cross-reference feature requirements with the Architecture & Design section.
2. **Flag Gaps**: If a touched component has status "⚠️ Missing", add a Bootstrapping Task to Phase N.
3. **Extract Context**: Include relevant artifacts in the "Relevant System Context" section of `plan.md`.

### For Task Generation (`/speckit.tasks`)

1. **Bind Context to Tasks**: For tasks touching specific modules, append `(Ref: <location>)` to task descriptions.
2. **Verify Prerequisites**: Check the Configuration & Infrastructure section for setup requirements.

### For Implementation (`/speckit.implement`)

1. **Follow Standards**: Reference the Code Style Guide and Development Guidelines.
2. **Check Decisions**: Review related ADRs before making architectural changes.

---

## Maintenance Protocol

### When a Feature is Completed

1. **Update Status**: Change artifact status from "⚠️ Missing" to "✅ Active".
2. **Record Location**: Fill in the actual file path or URL.
3. **Update Timestamp**: Set "Last Updated" to the current date.
4. **Add Description**: Briefly describe what the artifact contains.

### When an Artifact is Deprecated

1. **Change Status**: Mark as "🗑️ Deprecated".
2. **Add Reason**: Note why it was deprecated and what replaced it.
3. **Archive**: Move to an `archive/` directory if still needed for reference.

---

## Bootstrap Checklist

Review the Essential Artifacts tables above. Any artifact with status "⚠️ Missing" that is critical to your project should be prioritized for creation. The `/speckit.converge` phase will use this map to identify and close documentation gaps.

---

**Instructions for Agents**:

- **DO** treat this map as the authoritative index of documentation.
- **DO** propose updates to this map when creating or discovering new artifacts.
- **DO** flag missing artifacts during planning phases.
- **DO NOT** assume artifacts exist if not listed here or marked as "⚠️ Missing".
- **DO NOT** create duplicate documentation without updating this index.
- **DO NOT** add new sections or restructure this document. Only fill tables and update status fields.
- **DO NOT** add entries from `specs/` to this map. The `specs/` directory contains transient development artifacts (feature specs, plans, tasks). Their knowledge should be distilled into permanent documentation during the Converge phase — only those resulting permanent documents belong in this map.
