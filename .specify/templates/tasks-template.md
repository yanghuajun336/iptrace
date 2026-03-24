---

description: "Task list template for feature implementation"
---

# Tasks: [FEATURE NAME]

**Input**: Design documents from `/specs/[###-feature-name]/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: The examples below include test tasks. Tests are REQUIRED for all new features and bug fixes, in accordance with Article IV (Test-First Imperative) of the Constitution. All tasks MUST follow the Red-Green-Refactor cycle.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story?] [Skill?] Description`

- **[ID]**: Sequential task identifier (T001, T002, T003...); Phase N convergence tasks use `TN01, TN02...` prefix to visually distinguish them from implementation tasks
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- **[Skill: name]**: Indicates use of a specialized skill (e.g., `[Skill: speckit-developer]`); defaults to `[Skill: speckit-developer]` for implementation/test tasks when no domain skill is matched; **one skill per task** — if a task seems to require multiple skills, split it into smaller tasks
- Include exact file paths in descriptions

## Path Conventions

- **Single project**: `src/`, `tests/` at repository root
- **Web app**: `backend/src/`, `frontend/src/`
- **Mobile**: `api/src/`, `ios/src/` or `android/src/`
- Paths shown below assume single project - adjust based on plan.md structure

<!-- 
  ============================================================================
  IMPORTANT: The tasks below are SAMPLE TASKS for illustration purposes only.
  
  The /speckit.tasks command MUST replace these with actual tasks based on:
  - User stories from spec.md (with their priorities P1, P2, P3...)
  - Feature requirements from plan.md
  - Entities from data-model.md
  - Endpoints from contracts/
  
  **SKILL USAGE RULES**:
  - Check "Skill Alignment Strategy" in plan.md.
  - If a skill is identified, the task MUST be to use/execute that skill.
  - Prefix skill-based tasks with optional label: `[Skill: <name>]`.
  - Skills take precedence over manual implementation instructions.

  Tasks MUST be organized by user story so each story can be:
  - Implemented independently
  - Tested independently
  - Delivered as an MVP increment
  
  DO NOT keep these sample tasks in the generated tasks.md file.
  ============================================================================
-->

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [ ] T001 Create project structure per implementation plan
- [ ] T002 Initialize [language] project with [framework] dependencies
- [ ] T003 [P] Configure linting and formatting tools

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

Examples of foundational tasks (adjust based on your project):

- [ ] T004 Setup database schema and migrations framework
- [ ] T005 [P] Implement authentication/authorization framework
- [ ] T006 [P] Setup API routing and middleware structure
- [ ] T007 Create base models/entities that all stories depend on
- [ ] T008 Configure error handling and logging infrastructure
- [ ] T009 Setup environment configuration management

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - [Title] (Priority: P1) 🎯 MVP

**Goal**: [Brief description of what this story delivers]

**Independent Test**: [How to verify this story works on its own]

### Tests for User Story 1 (REQUIRED per Article IV) ✅

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T010 [P] [US1] Contract test for [endpoint] in tests/contract/test_[name].py
- [ ] T011 [P] [US1] Integration test for [user journey] in tests/integration/test_[name].py

### Implementation for User Story 1

- [ ] T012 [P] [US1] Create [Entity1] model in src/models/[entity1].py
- [ ] T013 [P] [US1] Create [Entity2] model in src/models/[entity2].py
- [ ] T014 [US1] Implement [Service] in src/services/[service].py (depends on T012, T013)
- [ ] T015 [US1] Implement [endpoint/feature] in src/[location]/[file].py
- [ ] T016 [US1] Add validation and error handling
- [ ] T017 [US1] Add logging for user story 1 operations

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - [Title] (Priority: P2)

**Goal**: [Brief description of what this story delivers]

**Independent Test**: [How to verify this story works on its own]

### Tests for User Story 2 (REQUIRED per Article IV) ✅

- [ ] T018 [P] [US2] Contract test for [endpoint] in tests/contract/test_[name].py
- [ ] T019 [P] [US2] Integration test for [user journey] in tests/integration/test_[name].py

### Implementation for User Story 2

- [ ] T020 [P] [US2] Create [Entity] model in src/models/[entity].py
- [ ] T021 [US2] Implement [Service] in src/services/[service].py
- [ ] T022 [US2] Implement [endpoint/feature] in src/[location]/[file].py
- [ ] T023 [US2] Integrate with User Story 1 components (if needed)

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - [Title] (Priority: P3)

**Goal**: [Brief description of what this story delivers]

**Independent Test**: [How to verify this story works on its own]

### Tests for User Story 3 (REQUIRED per Article IV) ✅

- [ ] T024 [P] [US3] Contract test for [endpoint] in tests/contract/test_[name].py
- [ ] T025 [P] [US3] Integration test for [user journey] in tests/integration/test_[name].py

### Implementation for User Story 3

- [ ] T026 [P] [US3] Create [Entity] model in src/models/[entity].py
- [ ] T027 [US3] Implement [Service] in src/services/[service].py
- [ ] T028 [US3] Implement [endpoint/feature] in src/[location]/[file].py

**Checkpoint**: All user stories should now be independently functional

---

[Add more user story phases as needed, following the same pattern]

---

## Phase N-1: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories  
**Scope**: Executed by `implement` command — this is the last phase before convergence

- [ ] TXXX [P] Documentation updates in docs/
- [ ] TXXX Code cleanup and refactoring
- [ ] TXXX Performance optimization across all stories
- [ ] TXXX [P] Additional unit tests in tests/unit/
- [ ] TXXX Security hardening
- [ ] TXXX Run quickstart.md validation

<!-- CONVERGENCE_BOUNDARY -->
<!-- Everything above this line is executed by /speckit.implement -->
<!-- Everything below this line is executed by /speckit.converge -->

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3)
- **Polish (Phase N-1)**: Depends on all desired user stories being complete
- **Convergence (Phase N)**: Depends on Polish completion — executed by `/speckit.converge`

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - May integrate with US1 but should be independently testable
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - May integrate with US1/US2 but should be independently testable

### Within Each User Story

- Tests MUST be written and FAIL before implementation (Article IV)
- Models before services
- Services before endpoints
- Core implementation before integration
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, all user stories can start in parallel (if team capacity allows)
- All tests for a user story marked [P] can run in parallel
- Models within a story marked [P] can run in parallel
- Different user stories can be worked on in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Launch all tests for User Story 1 together:
Task: "Contract test for [endpoint] in tests/contract/test_[name].py"
Task: "Integration test for [user journey] in tests/integration/test_[name].py"

# Launch all models for User Story 1 together:
Task: "Create [Entity1] model in src/models/[entity1].py"
Task: "Create [Entity2] model in src/models/[entity2].py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1
   - Developer B: User Story 2
   - Developer C: User Story 3
3. Stories complete and integrate independently

---

## Phase N: System Convergence

**Purpose**: Close the documentation feedback loop and maintain system integrity  
**Scope**: Executed by `/speckit.converge` — NOT by `/speckit.implement`

**⚠️ REQUIRED**: This phase ensures feature artifacts are merged back into system documentation

<!--
  SPECS/ DISTILLATION RULE (MANDATORY):
  
  The `specs/` directory contains transient AI Agent work products (spec.md, plan.md, tasks.md,
  data-model.md, etc.). These are INPUTS for knowledge distillation — NOT outputs to be indexed.

  Phase N tasks MUST:
  - Extract knowledge from specs/ artifacts and write it into permanent project documentation
    (ADRs, architecture docs, API guides, configuration guides, etc.)
  - Reference only those resulting permanent documents in memory/system-map.md

  Phase N tasks MUST NOT:
  - Add any specs/ file paths as entries in memory/system-map.md
  - Leave direct links or references to specs/ files in system-map.md

  If memory/system-map.md already contains entries pointing into specs/, include a task to
  aggregate that content into proper permanent docs and remove the specs/ references from the map.
-->

### Documentation Updates

<!--
  STRATEGY: Based on "Documentation State Matrix" from plan.md
-->

**ADR (Architecture Decision Records)**:
- [ ] TN01 [Skill: speckit-librarian] Create ADR for [significant decision] in docs/adr/[####-title].md
- [ ] TN02 [Skill: speckit-librarian] Update ADR index with new decisions

**System Documentation**:
- [ ] TN03 [Skill: speckit-librarian] Update Architecture Diagram to reflect [new component]
- [ ] TN04 [Skill: speckit-librarian] Update API Documentation with [new endpoints]
- [ ] TN05 [P] [Skill: speckit-librarian] Update Configuration Guide with [new settings]

**System Map Synchronization**:
- [ ] TN06 [Skill: speckit-librarian] Update memory/system-map.md:
  - Change artifact status from "⚠️ Missing" to "✅ Active"
  - Add locations for newly created **permanent** documents (docs/, ADRs, guides — never specs/)
  - Record "Last Updated" timestamps
  - Add descriptions of new artifacts
  - **Remove any existing entries that point into `specs/`** — if found, distill their content
    into a proper permanent document first, then replace the specs/ reference with that document

### Bootstrapping (Gap Closure)

<!--
  STRATEGY: Based on "Gap Analysis" from plan.md
-->

**Missing Essential Artifacts** (if flagged in plan.md):
- [ ] TN07 Create [missing artifact] in [location] (Ref: plan.md Gap Analysis)
- [ ] TN08 Notify [team] of new artifact availability

### Validation

**TDD Compliance Verification**:
- [ ] TN09 Verify all implementation tasks have corresponding test tasks
- [ ] TN10 Confirm test coverage meets project standards (per constitution)

**Documentation Completeness**:
- [ ] TN11 Verify all changes from "Documentation State Matrix" are complete
- [ ] TN12 Ensure System Map accurately reflects current system state
- [ ] TN13 [Skill: speckit-librarian] Confirm memory/system-map.md contains no entries referencing specs/ paths

---

## Test-Driven Development (TDD) Rules

**MANDATORY**: All implementation tasks MUST follow Red-Green-Refactor cycle:

### 🔴 RED Phase
1. Write a test that captures the requirement
2. Run the test and confirm it **FAILS**
3. Output: "Test created at `tests/...` and confirmed failing"

### 🟢 GREEN Phase
1. Write **minimum code** to make the test pass
2. Run the test and confirm it **PASSES**
3. No over-engineering at this stage

### 🔵 REFACTOR Phase
1. Clean up the code while keeping tests green
2. Improve naming, remove duplication
3. Ensure tests still pass after cleanup

**Task Pairing**: Every implementation task should be preceded by its test task:
- Example: T015 (Test User model) → T016 (Implement User model)

---

## Notes

- [P] tasks = different files, no dependencies
- [Skill: name] = uses specialized skill from skills/ directory
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- **TDD REQUIRED**: Verify tests fail (RED) before implementing (GREEN), then refactor (REFACTOR)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
