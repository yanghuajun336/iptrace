---
description: Execute the System Convergence phase — update documentation, close gaps, and synchronize the system map.
handoffs:
  - label: Analyze For Consistency
    agent: speckit.analyze
    prompt: Run a project analysis for consistency
    send: true
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

1. **Setup**: Run `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` from repo root and parse FEATURE_DIR and AVAILABLE_DOCS list. All paths must be absolute.

2. **Load active skills**: Run `python3 .specify/scripts/resolve-skills.py converge .` from repo root and read the **entire output**. The skills returned are **MANDATORY** for this phase — you MUST adopt their personas and follow all workflow steps they define with highest priority. Do not simplify or skip any steps.

3. **Locate Convergence Tasks**: Read `tasks.md` and find the `<!-- CONVERGENCE_BOUNDARY -->` marker.
   - Extract all tasks **below** the boundary (Phase N: System Convergence).
   - If no boundary marker found, report error and suggest running `/speckit.tasks` to regenerate.

4. **Verify Pre-conditions**:
   - Check that all tasks **above** the boundary (Phases 1 through N-1) are marked as `[X]` (complete).
   - If incomplete tasks exist above the boundary, **STOP** and report:
     - List of incomplete tasks with their IDs
     - Prompt user: "Implementation tasks are not complete. Run `/speckit.implement` first."
   - If all pre-implementation tasks are complete, proceed.

5. **Load Convergence Context**:
   - **REQUIRED**: Read `plan.md` — extract "Documentation State Matrix" and "Gap Analysis" sections
   - **REQUIRED**: Read `.specify/memory/system-map.md` — current documentation index
     - If `.specify/memory/system-map.md` does **not** exist, **STOP** and prompt the user: "System Map not found. Run `/speckit.constitution` first to initialize project memory files (constitution + system-map)."
   - **IF EXISTS**: Read `.specify/memory/constitution.md` — governance principles
   - **KNOWLEDGE DISTILLATION**: Read all artifacts in the current feature's specs directory (spec.md, plan.md, tasks.md, and any other documents) as knowledge input sources. Extract architectural decisions, design intent, and implementation context to inform the documentation you will produce.

6. **Execute Phase N Tasks** in order:
   - For each task in the convergence phase:
     a. Read the task description and any `(Ref: ...)` context
     b. Execute the task following skill instructions
     c. Mark the task as `[X]` in tasks.md upon completion
   - **Task Categories**:
     - **ADR Tasks**: Create/update Architecture Decision Records in `docs/adr/`
     - **Documentation Tasks**: Update architecture docs, API docs, configuration guides
     - **System Map Tasks**: Synchronize `.specify/memory/system-map.md` with actual file state
     - **Gap Closure Tasks**: Create missing essential artifacts flagged in plan.md
     - **Validation Tasks**: Verify documentation completeness and TDD compliance

7. **Convergence Validation**:
   - Verify every entry in plan.md "Documentation State Matrix" has a completed task
   - Verify every entry in plan.md "Gap Analysis" has a completed bootstrapping task
   - Verify `.specify/memory/system-map.md` reflects the current state of all artifacts
   - Report any unclosed items as warnings

8. **Convergence Report**: Output summary including:
   - Documents updated (with paths)
   - ADRs created/updated
   - Gaps closed
   - System Map changes
   - Any remaining warnings or manual actions needed
   - Suggest running `/speckit.analyze` for final consistency check

## Key Rules

- Use absolute paths for all file operations
- Follow the speckit-librarian skill workflow strictly
- ADRs must use Michael Nygard format (Title, Status, Context, Decision, Consequences)
- System Map paths must be RELATIVE from repo root
- Do NOT modify implementation code — this phase is documentation-only
- **`specs/` are knowledge INPUT, not documentation OUTPUT**: The feature's specs directory is a source for distillation. Never add `specs/` entries to `.specify/memory/system-map.md`. The resulting permanent documents (ADRs, architecture docs, guides) are what gets indexed.
