---
description: Execute the implementation planning workflow using the plan template to generate design artifacts.
handoffs: 
  - label: Create Tasks
    agent: speckit.tasks
    prompt: Break the plan into tasks
    send: true
  - label: Create Checklist
    agent: speckit.checklist
    prompt: Create a checklist for the following domain...
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

1. **Setup**: Run `.specify/scripts/bash/setup-plan.sh --json` from repo root and parse JSON for FEATURE_SPEC, IMPL_PLAN, SPECS_DIR, BRANCH. For single quotes in args like "I'm Groot", use escape syntax: e.g 'I'\''m Groot' (or double-quote if possible: "I'm Groot").

2. **Load Active Skills**: Run `python3 .specify/scripts/resolve-skills.py plan .` from repo root and read the **entire output**. The skills returned are **MANDATORY** for this phase — you MUST adopt their personas and follow all workflow steps they define with highest priority. Do not simplify or skip any steps.

3. **Load context**: Read FEATURE_SPEC and `.specify/memory/constitution.md`. Load IMPL_PLAN template (already copied).

4. **Execute plan workflow**: Follow the structure in IMPL_PLAN template to:
   - Fill Technical Context (mark unknowns as "NEEDS CLARIFICATION")
   - Fill Constitution Check section from constitution
   - Evaluate gates (ERROR if violations unjustified)
   - **System Map Integration** (if `.specify/memory/system-map.md` exists):
     - Read `.specify/memory/system-map.md` and identify which components are touched by this feature
     - Fill the "Relevant System Context" section with 3-5 key documents from the System Map
     - Complete the "Documentation State Matrix" for all impacted documents (action: Create/Update/Review)
     - Run "Gap Analysis" against the System Map's Essential Artifacts list:
       - For each artifact marked "⚠️ Missing" in the System Map table:
         - **Verify on disk first**: run `ls <location>` to confirm the file does not exist
         - If confirmed absent → add a Bootstrapping Task to Phase N
         - If the file **exists on disk** but is marked "⚠️ Missing" → update its status to "✅ Active" in the System Map; do NOT add a Bootstrapping Task
   - Phase 0: Generate research.md (resolve all NEEDS CLARIFICATION)
   - Phase 1: Generate data-model.md, contracts/, quickstart.md
   - Phase 1: Update agent context by running the agent script
   - **Skill Alignment**:
     - Check `spec.md` for "Available Skills Analysis" and "Linked Skills" in User Stories.
     - Map requirements to available skills in `plan.md` under "Skill Alignment Strategy".
     - **Workflow Injection**:
       - READ the mapped Skill's `SKILL.md` in its **ENTIRETY**. You MUST NOT skip sections or only read summaries.
       - Look for "Standard Development Workflow", "Process", or "Verification" sections.
       - You MUST incorporate these mandatory workflow steps (e.g., "Run Pipeline Simulation", "Update Client Scripts") into your Plan phases.
       - **STRICT COMPLIANCE**: If a skill defines a workflow, you MUST strictly follow it. You are PROHIBITED from simplifying or skipping steps defined in a skill.
     - Ensure the plan relies on skills where applicable.
   - Re-evaluate Constitution Check post-design

5. **Stop and report**: Command ends after Phase 2 planning. Report branch, IMPL_PLAN path, and generated artifacts.

## Phases

### Phase 0: Outline & Research

1. **Extract unknowns from Technical Context** above:
   - For each NEEDS CLARIFICATION → research task
   - For each dependency → best practices task
   - For each integration → patterns task

2. **Generate and dispatch research agents**:

   ```text
   For each unknown in Technical Context:
     Task: "Research {unknown} for {feature context}"
   For each technology choice:
     Task: "Find best practices for {tech} in {domain}"
   ```

3. **Consolidate findings** in `research.md` using format:
   - Decision: [what was chosen]
   - Rationale: [why chosen]
   - Alternatives considered: [what else evaluated]

**Output**: research.md with all NEEDS CLARIFICATION resolved

### Phase 1: Design & Contracts

**Prerequisites:** `research.md` complete

1. **Extract entities from feature spec** → `data-model.md`:
   - Entity name, fields, relationships
   - Validation rules from requirements
   - State transitions if applicable
   - **If no new data models**: still create `data-model.md` containing only an N/A declaration that explains why no models are needed

2. **Generate API contracts** from functional requirements:
   - For each user action → endpoint
   - Use standard REST/GraphQL patterns
   - Output OpenAPI/GraphQL schema to `/contracts/`
   - **If no API contracts**: still create `contracts/README.md` containing only an N/A declaration

3. **Generate quickstart.md** for user-facing features:
   - Prerequisites, setup steps, and usage examples
   - **If not user-facing** (e.g., pure testing or internal tooling feature): still create `quickstart.md` containing only an N/A declaration

4. **Agent context update**:
   - Run `.specify/scripts/bash/update-agent-context.sh copilot`
   - These scripts detect which AI agent is in use
   - Update the appropriate agent-specific context file
   - Add only new technology from current plan
   - Preserve manual additions between markers

**Output**: data-model.md, contracts/README.md (or full contracts), quickstart.md, agent-specific file

## Key rules

- Use absolute paths
- ERROR on gate failures or unresolved clarifications
- **Design depth limit**: Plan phase defines *what* to build — entity names, contract shapes, test names, assertion directions, coverage targets. It does NOT define *how* to build it — no complete function signatures, no mock parameter lists, no Before/After code snippets, no full test skeletons. Implementation details belong in `/speckit.tasks` output.
