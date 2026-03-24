---
description: Perform a non-destructive cross-artifact consistency and quality analysis across spec.md, plan.md, and tasks.md after task generation.
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Goal

Identify inconsistencies, duplications, ambiguities, and underspecified items across the three core artifacts (`spec.md`, `plan.md`, `tasks.md`) before implementation. **Verify that the project strictly adheres to the workflows and mandates defined in relevant Skills.** This command MUST run only after `/speckit.tasks` has successfully produced a complete `tasks.md`.

## Operating Constraints

**STRICTLY READ-ONLY**: Do **not** modify any files. Output a structured analysis report. Offer an optional remediation plan (user must explicitly approve before any follow-up editing commands would be invoked manually).

**Constitution & Skill Authority**: The project constitution (`.specify/memory/constitution.md`) and **active Skills** are **non-negotiable** within this analysis scope. Conflicts with Constitution or Skills are automatically CRITICAL.

## Execution Steps

### 1. Initialize Analysis Context

Run `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` once from repo root and parse JSON for FEATURE_DIR and AVAILABLE_DOCS. Derive absolute paths:

- SPEC = FEATURE_DIR/spec.md
- PLAN = FEATURE_DIR/plan.md
- TASKS = FEATURE_DIR/tasks.md

Abort with an error message if any required file is missing (instruct the user to run missing prerequisite command).
For single quotes in args like "I'm Groot", use escape syntax: e.g 'I'\''m Groot' (or double-quote if possible: "I'm Groot").

### 2. Load Artifacts (Progressive Disclosure)

Load only the minimal necessary context from each artifact:

**From spec.md:**

- Overview/Context
- Functional Requirements
- Non-Functional Requirements
- User Stories
- Edge Cases (if present)

**From plan.md:**

- Architecture/stack choices
- Data Model references
- Phases
- Technical constraints

**From tasks.md:**

- Task IDs
- Descriptions
- Phase grouping
- Parallel markers [P]
- Referenced file paths

**From constitution:**

- Load `.specify/memory/constitution.md` for principle validation

**From system map:**

- Load `.specify/memory/system-map.md` (if it exists) for structure and reference validation

**From active skills:**

- Identify used skills from `spec.md` ("Linked Skills") or `plan.md` ("Skill Alignment Strategy")
- Load `SKILL.md` content for each identified skill
- **Context Extraction Strategy**: Instead of relying on specific section headers, analyze the content to identify:
  - Procedural workflows (ordered steps)
  - Mandatory requirements (MUST/REQUIRED)
  - Technical constraints and prohibited patterns
  - Verification steps and criteria

### 3. Build Semantic Models

Create internal representations (do not include raw artifacts in output):

- **Requirements inventory**: Each functional + non-functional requirement with a stable key
- **User story/action inventory**: Discrete user actions with acceptance criteria
- **Task coverage mapping**: Map each task to one or more requirements or stories
- **Constitution rule set**: Extract principle names and MUST/SHOULD normative statements
- **Skill Workflow Model**: Extract sequential steps and mandatory actions from Skills

### 4. Detection Passes (Token-Efficient Analysis)

Focus on high-signal findings. Limit to 50 findings total; aggregate remainder in overflow summary.

#### A. Duplication Detection

- Identify near-duplicate requirements
- Mark lower-quality phrasing for consolidation

#### B. Ambiguity Detection

- Flag vague adjectives (fast, scalable, secure, intuitive, robust) lacking measurable criteria
- Flag unresolved placeholders (TODO, TKTK, ???, `<placeholder>`, etc.)

#### C. Underspecification

- Requirements with verbs but missing object or measurable outcome
- User stories missing acceptance criteria alignment
- Tasks referencing files or components not defined in spec/plan

#### D. Constitution & Skill Alignment

- Any requirement or plan element conflicting with a MUST principle
- Missing mandated sections or quality gates from constitution
- **Skill Deviation**:
  - `plan.md`: Phases do not match Skill's identified procedural workflows
  - `tasks.md`: Tasks omit steps mandated by Skill (e.g., "Run Pipeline Simulation")
  - `spec.md`: Requirements contradict Skill's constraints
  - **Simplification Check**: Detect if tasks merge discrete Skill steps into single generic tasks (Forbidden)

#### E. Coverage Gaps

- Requirements with zero associated tasks
- Tasks with no mapped requirement/story
- Non-functional requirements not reflected in tasks (e.g., performance, security)

#### F. Inconsistency

- Terminology drift (same concept named differently across files)
- Data entities referenced in plan but absent in spec (or vice versa)
- Task ordering contradictions (e.g., integration tasks before foundational setup tasks without dependency note)
- Conflicting requirements (e.g., one requires Next.js while other specifies Vue)

#### G. Phase N Coverage Check

- Verify plan.md "Documentation State Matrix" has ≥1 corresponding task in tasks.md Phase N (after `<!-- CONVERGENCE_BOUNDARY -->`)
- Verify plan.md "Gap Analysis" has ≥1 bootstrapping task in tasks.md Phase N
- Verify `<!-- CONVERGENCE_BOUNDARY -->` marker exists in tasks.md (if Phase N tasks are present)
- Flag any Documentation State Matrix entry without a Phase N task as **CRITICAL**
- Flag any Gap Analysis entry without a bootstrapping task as **HIGH**
- Flag missing CONVERGENCE_BOUNDARY marker as **HIGH** (implement command cannot enforce boundary)

#### H. System Map Validation

Read `.specify/memory/system-map.md` if it exists; if the file is absent, flag as **CRITICAL** and skip sub-checks.

**Structure Integrity** — Verify every required section heading is present:

- `# System Map` (H1 title)
- `## Project Identity`
- `## Essential Artifacts`
- `### 🏛️ Architecture & Design`
- `### 📐 Configuration & Infrastructure`
- `### 🧪 Quality & Testing`
- `### 🧭 Project Memory`
- `### 📚 Decisions & Standards`
- `## Integration Points`
- `## Knowledge Sources`
- `## Using the System Map`
- `## Maintenance Protocol`
- `## Bootstrap Checklist`

Flag each missing required section as **HIGH**. Flag a missing H1 title (`# System Map`) as **CRITICAL** (document is unrecognisable as a system map).

**Forbidden Reference Check** — Scan every Location column value across all artifact tables in the system map:

- Flag any Location that starts with `specs/`, `./specs/`, `../specs/`, or `specs\` as **CRITICAL**
- The `specs/` directory holds transient development artifacts (feature specs, plans, tasks). Their knowledge must be distilled into permanent documentation during the Converge phase; only those resulting permanent documents belong in the system map.
- Report the full artifact row (Artifact name + Location value) for each violation to make remediation straightforward.

### 5. Severity Assignment

Use this heuristic to prioritize findings:

- **CRITICAL**: Violates constitution MUST or **Skill Mandate**, missing core spec artifact, or requirement with zero coverage
- **HIGH**: Duplicate or conflicting requirement, ambiguous security/performance attribute, untestable acceptance criterion
- **MEDIUM**: Terminology drift, missing non-functional task coverage, underspecified edge case
- **LOW**: Style/wording improvements, minor redundancy not affecting execution order

### 6. Produce Compact Analysis Report

Output a Markdown report (no file writes) with the following structure:

## Specification Analysis Report

| ID | Category | Severity | Location(s) | Summary | Recommendation |
|----|----------|----------|-------------|---------|----------------|
| A1 | Duplication | HIGH | spec.md:L120-134 | Two similar requirements ... | Merge phrasing; keep clearer version |

(Add one row per finding; generate stable IDs prefixed by category initial.)

**Coverage Summary Table:**

| Requirement Key | Has Task? | Task IDs | Notes |
|-----------------|-----------|----------|-------|

**Constitution Alignment Issues:** (if any)

**Unmapped Tasks:** (if any)

**Metrics:**

- Total Requirements
- Total Tasks
- Coverage % (requirements with >=1 task)
- Ambiguity Count
- Duplication Count
- Critical Issues Count

### 7. Provide Next Actions

At end of report, output a concise Next Actions block:

- If CRITICAL issues exist: Recommend resolving before `/speckit.implement`
- If only LOW/MEDIUM: User may proceed, but provide improvement suggestions
- Provide explicit command suggestions: e.g., "Run /speckit.specify with refinement", "Run /speckit.plan to adjust architecture", "Manually edit tasks.md to add coverage for 'performance-metrics'"

### 8. Offer Remediation

Ask the user: "Would you like me to suggest concrete remediation edits for the top N issues?" (Do NOT apply them automatically.)

## Operating Principles

### Context Efficiency

- **Minimal high-signal tokens**: Focus on actionable findings, not exhaustive documentation
- **Progressive disclosure**: Load artifacts incrementally; don't dump all content into analysis
- **Token-efficient output**: Limit findings table to 50 rows; summarize overflow
- **Deterministic results**: Rerunning without changes should produce consistent IDs and counts

### Analysis Guidelines

- **NEVER modify files** (this is read-only analysis)
- **NEVER hallucinate missing sections** (if absent, report them accurately)
- **Prioritize constitution violations** (these are always CRITICAL)
- **Use examples over exhaustive rules** (cite specific instances, not generic patterns)
- **Report zero issues gracefully** (emit success report with coverage statistics)

## Context

$ARGUMENTS
