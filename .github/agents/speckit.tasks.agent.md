---
description: Generate an actionable, dependency-ordered tasks.md for the feature based on available design artifacts.
handoffs: 
  - label: Analyze For Consistency
    agent: speckit.analyze
    prompt: Run a project analysis for consistency
    send: true
  - label: Implement Project
    agent: speckit.implement
    prompt: Start the implementation in phases
    send: true
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

1. **Setup**: Run `.specify/scripts/bash/check-prerequisites.sh --json` from repo root and parse FEATURE_DIR and AVAILABLE_DOCS list. All paths must be absolute. For single quotes in args like "I'm Groot", use escape syntax: e.g 'I'\''m Groot' (or double-quote if possible: "I'm Groot").

2. **Load active skills**: Run `python3 .specify/scripts/resolve-skills.py tasks .` from repo root and read the **entire output**. The skills returned are **MANDATORY** for this phase — you MUST adopt their personas and follow all workflow steps they define with highest priority. Do not simplify or skip any steps.

3. **Load design documents**: Read from FEATURE_DIR:
   - **Required**: plan.md (tech stack, libraries, structure), spec.md (user stories with priorities)
   - **Optional**: data-model.md (entities), contracts/ (API endpoints), research.md (decisions), quickstart.md (test scenarios)
   - Note: Not all projects have all documents. Generate tasks based on what's available.

4. **Execute task generation workflow**:
   - Load plan.md and extract tech stack, libraries, project structure
   - Load spec.md and extract user stories with their priorities (P1, P2, P3, etc.)
   - If data-model.md exists: Extract entities and map to user stories
   - If contracts/ exists: Map endpoints to user stories
   - If research.md exists: Extract decisions for setup tasks
   - **Skill Integration**:
     - specific Check `plan.md` for "Skill Alignment Strategy".
     - For any requirement mapped to a skill, creating a task to *use/execute* that skill.
     - **Strict Adherence**: Ensure tasks strictly reflect the workflow steps defined in the skill. Do not simplify or merge steps if the skill prescribes a specific sequence.
     - Label such tasks with `[Skill: Name]`.
     - **Default fallback**: If no domain skill is matched for a user story, label its implementation and test tasks with `[Skill: speckit-developer]`.
   - Generate tasks organized by user story (see Task Generation Rules below)
   - Generate dependency graph showing user story completion order
   - Create parallel execution examples per user story
   - **Phase N-1 & N Generation**:
     - Generate "Phase N-1: Polish & Cross-Cutting Concerns" tasks (code cleanup, refactoring, security)
     - Insert `<!-- CONVERGENCE_BOUNDARY -->` marker after Phase N-1
     - Generate "Phase N: System Convergence" tasks based on:
       - plan.md "Documentation State Matrix" → documentation update tasks
       - plan.md "Gap Analysis" → bootstrapping tasks for missing artifacts
       - System Map synchronization task
       - ADR creation tasks (if architectural decisions were made)
     - Label all Phase N tasks with `[Skill: speckit-librarian]`
     - **⚠️ `specs/` distillation rule**: Phase N tasks MUST distill `specs/` content into
       permanent project documentation (ADRs, architecture docs, guides, etc.). Tasks MUST NOT
       instruct adding `specs/` file paths to `.specify/memory/system-map.md` — the system map indexes
       only permanent, human-readable documentation, not transient AI Agent work products stored
       under `specs/`. If `.specify/memory/system-map.md` already contains entries pointing into `specs/`,
       generate an explicit task to aggregate that content into proper project docs and then remove
       the `specs/` references from the map.
   - Validate task completeness (each user story has all needed tasks, independently testable)

5. **Generate tasks.md**: Use `.specify/templates/tasks-template.md` as structure, fill with:
   - Correct feature name from plan.md
   - Phase 1: Setup tasks (project initialization)
   - Phase 2: Foundational tasks (blocking prerequisites for all user stories)
   - Phase 3+: One phase per user story (in priority order from spec.md)
   - Each phase includes: story goal, independent test criteria, tests (if requested), implementation tasks
   - Final Phase: Polish & cross-cutting concerns
   - All tasks must follow the strict checklist format (see Task Generation Rules below)
   - Clear file paths for each task
   - Dependencies section showing story completion order
   - Parallel execution examples per story
   - Implementation strategy section (MVP first, incremental delivery)

6. **Report**: Output path to generated tasks.md and summary:
   - Total task count
   - Task count per user story
   - Parallel opportunities identified
   - Independent test criteria for each story
   - Suggested MVP scope (typically just User Story 1)
   - Format validation: Confirm ALL tasks follow the checklist format (checkbox, ID, labels, file paths)

Context for task generation: $ARGUMENTS

The tasks.md should be immediately executable - each task must be specific enough that an LLM can complete it without additional context.

## Task Generation Rules

**CRITICAL**: Tasks MUST be organized by user story to enable independent implementation and testing.

**Tests are REQUIRED**: All implementation tasks MUST have corresponding test tasks, in accordance with Article IV (Test-First Imperative) of the Constitution. Follow the Red-Green-Refactor cycle.

### Checklist Format (REQUIRED)

Every task MUST strictly follow this format:

```text
- [ ] [TaskID] [P?] [Story?] [Skill?] Description with file path
```

**Format Components**:

1. **Checkbox**: ALWAYS start with `- [ ]` (markdown checkbox)
2. **Task ID**: Sequential number (T001, T002, T003...) in execution order
3. **[P] marker**: Include ONLY if task is parallelizable (different files, no dependencies on incomplete tasks)
4. **[Story] label**: REQUIRED for user story phase tasks only
   - Format: [US1], [US2], [US3], etc. (maps to user stories from spec.md)
   - Setup phase: NO story label
   - Foundational phase: NO story label  
   - User Story phases: MUST have story label
   - Polish phase: NO story label
5. **[Skill] label**: Include when a task uses a specialized skill
   - Format: [Skill: name], e.g. `[Skill: speckit-developer]`, `[Skill: speckit-librarian]`
   - If no domain skill is matched in plan.md "Skill Alignment Strategy", implementation tasks default to `[Skill: speckit-developer]`
   - Phase N convergence tasks always use `[Skill: speckit-librarian]`
   - Omit when no skill applies (e.g. simple setup steps)
   - **One skill per task** — if a task seems to require multiple skills, split it into smaller tasks
6. **Description**: Clear action with exact file path

**Examples**:

- ✅ CORRECT: `- [ ] T001 Create project structure per implementation plan`
- ✅ CORRECT: `- [ ] T005 [P] Implement authentication middleware in src/middleware/auth.py`
- ✅ CORRECT: `- [ ] T012 [P] [US1] Create User model in src/models/user.py`
- ✅ CORRECT: `- [ ] T014 [US1] [Skill: speckit-developer] Implement UserService in src/services/user_service.py`
- ✅ CORRECT: `- [ ] T035 [P] [Skill: speckit-developer] Run pytest tests/ -v and confirm zero failures`
- ✅ CORRECT: `- [ ] TN01 [Skill: speckit-librarian] Update CHANGELOG.md with behavioral fix entry`
- ❌ WRONG: `- [ ] Create User model` (missing ID and Story label)
- ❌ WRONG: `T001 [US1] Create model` (missing checkbox)
- ❌ WRONG: `- [ ] [US1] Create User model` (missing Task ID)
- ❌ WRONG: `- [ ] T001 [US1] Create model` (missing file path)

### Task Organization

1. **From User Stories (spec.md)** - PRIMARY ORGANIZATION:
   - Each user story (P1, P2, P3...) gets its own phase
   - Map all related components to their story:
     - Models needed for that story
     - Services needed for that story
     - Endpoints/UI needed for that story
     - If tests requested: Tests specific to that story
   - Mark story dependencies (most stories should be independent)

2. **From Contracts**:
   - Map each contract/endpoint → to the user story it serves
   - If tests requested: Each contract → contract test task [P] before implementation in that story's phase

3. **From Data Model**:
   - Map each entity to the user story(ies) that need it
   - If entity serves multiple stories: Put in earliest story or Setup phase
   - Relationships → service layer tasks in appropriate story phase

4. **From Setup/Infrastructure**:
   - Shared infrastructure → Setup phase (Phase 1)
   - Foundational/blocking tasks → Foundational phase (Phase 2)
   - Story-specific setup → within that story's phase

### Phase Structure

- **Phase 1**: Setup (project initialization)
- **Phase 2**: Foundational (blocking prerequisites - MUST complete before user stories)
- **Phase 3+**: User Stories in priority order (P1, P2, P3...)
  - Within each story: Tests → Models → Services → Endpoints → Integration
  - Each phase should be a complete, independently testable increment
- **Phase N-1**: Polish & Cross-Cutting Concerns (last phase executed by `/speckit.implement`)
- `<!-- CONVERGENCE_BOUNDARY -->` — hard boundary marker
- **Phase N**: System Convergence (executed by `/speckit.converge`, NOT by `/speckit.implement`)
