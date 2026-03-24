---
description: Create or update the feature specification from a natural language feature description.
handoffs: 
  - label: Build Technical Plan
    agent: speckit.plan
    prompt: Create a plan for the spec. I am building with...
  - label: Clarify Spec Requirements
    agent: speckit.clarify
    prompt: Clarify specification requirements
    send: true
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

The text the user typed after `/speckit.specify` in the triggering message **is** the feature description. Assume you always have it available in this conversation even if `$ARGUMENTS` appears literally below. Do not ask the user to repeat it unless they provided an empty command.

Given that feature description, do this:

1. **Detect workflow mode**:
   
   Check if the user provided a `--spec-dir` parameter in their input:
   - If `--spec-dir <path>` is present: Use **Mode A** (existing directory workflow)
   - Otherwise: Use **Mode B** (auto-create directory workflow - original behavior)

2. **Mode A: Existing Directory Workflow** (when `--spec-dir` provided):
   
   a. Extract the directory path from user input after `--spec-dir`
   
   b. Determine the branch type: check if `--type <type>` is provided (default: `feat`). Valid types: `feat`, `bug`, `hotfix`, `refactor`, `docs`, `chore`.
   
   c. Run the script with the spec-dir and type parameters:
      ```bash
      .specify.specify/scripts/bash/create-new-feature.sh --json --type feat --spec-dir "specs/001-feature-name/" "$ARGUMENTS"
      ```
   
   d. The script will:
      - Validate the directory exists and is writable
      - Extract spec name from directory path (e.g., `specs/001-oauth-integration/` → `001-oauth-integration`)
      - Build branch name with type prefix (e.g., `feat/001-oauth-integration`)
      - Create or checkout the branch
      - Initialize spec.md in the existing directory
   
   e. Skip to step 3 (Load template)
   
   **Example usage**:
   ```bash
   /speckit.specify --spec-dir specs/001-oauth-integration/ "Add OAuth2 authentication"
   /speckit.specify --type bug --spec-dir specs/002-login-crash/ "Fix login crash"
   ```

3. **Mode B: Auto-Create Directory Workflow** (when `--spec-dir` NOT provided - original behavior):

   a. **Determine branch type**: Analyze the feature description to select the appropriate branch type, or use `--type <type>` if provided. Default: `feat`. Valid types: `feat`, `bug`, `hotfix`, `refactor`, `docs`, `chore`.
      - Feature/new functionality → `feat`
      - Bug fix → `bug`
      - Emergency production fix → `hotfix`
      - Code restructuring → `refactor`
      - Documentation changes → `docs`
      - Build/tooling/dependency changes → `chore`

   b. **Generate a concise short name** (2-4 words) for the branch:
      - Analyze the feature description and extract the most meaningful keywords
      - Create a 2-4 word short name that captures the essence of the feature
      - Use action-noun format when possible (e.g., "user-auth", "payment-timeout")
      - Preserve technical terms and acronyms (OAuth2, API, JWT, etc.)
      - Keep it concise but descriptive enough to understand the feature at a glance
      - Examples:
        - "I want to add user authentication" → type: `feat`, short-name: "user-auth"
        - "Fix payment processing timeout bug" → type: `bug`, short-name: "payment-timeout"
        - "Emergency fix for database connection" → type: `hotfix`, short-name: "db-connection"
        - "Refactor the authentication module" → type: `refactor`, short-name: "auth-module"

   c. **Check for existing branches before creating new one**:

      i. First, fetch all remote branches to ensure we have the latest information:

         ```bash
         git fetch --all --prune
         ```

      ii. Find the highest feature number across all sources for the short-name:
         - Remote branches: `git ls-remote --heads origin | grep -E 'refs/heads/(feat|bug|hotfix|refactor|docs|chore)/[0-9]+-'`
         - Local branches: `git branch | grep -E '(feat|bug|hotfix|refactor|docs|chore)/[0-9]+-'`
         - Specs directories: Check for directories matching `specs/[0-9]+-<short-name>`

      iii. Determine the next available number:
         - Extract all numbers from all three sources
         - Find the highest number N
         - Use N+1 for the new branch number

      iv. Run the script `.specify/scripts/bash/create-new-feature.sh --json "$ARGUMENTS"` with the calculated number, type, and short-name:
         - Pass `--type <type> --number N+1 --short-name "your-short-name"` along with the feature description
         - Bash example: `.specify/scripts/bash/create-new-feature.sh --json "$ARGUMENTS" --json --type feat --number 5 --short-name "user-auth" "Add user authentication"`
         - PowerShell example: `.specify/scripts/bash/create-new-feature.sh --json "$ARGUMENTS" -Json -Type feat -Number 5 -ShortName "user-auth" "Add user authentication"`

      **IMPORTANT**:
      - Check all three sources (remote branches, local branches, specs directories) to find the highest number
      - Only match branches/directories with the exact short-name pattern
      - If no existing branches/directories found with this short-name, start with number 1
      - You must only ever run this script once per feature
      - The JSON is provided in the terminal as output - always refer to it to get the actual content you're looking for
      - The JSON output will contain BRANCH_NAME, SPEC_FILE, and BRANCH_TYPE
      - Branch name format: `type/###-short-name` (e.g., `feat/001-user-auth`, `bug/002-login-crash`)
      - For single quotes in args like "I'm Groot", use escape syntax: e.g 'I'\''m Groot' (or double-quote if possible: "I'm Groot")

4. **Load template and continue**: After either Mode A or B completes, continue with the rest of the workflow (load template, skill analysis, etc.)

5. Load `.specify/templates/spec-template.md` to understand required sections.

6. **Skill Analysis (CRITICAL)**:
   - READ the `SKILL.md` file for any relevant skill in its entirety. You cannot pick and choose sections; you must understand the full context.
   - If a requirement falls under a skill's domain, you MUST plan to use that skill.
   - Skill workflows are AUTHORITATIVE. You cannot simplify them.

7. Follow this execution flow:

    1. Parse user description from Input
       If empty: ERROR "No feature description provided"
    2. Extract key concepts from description
       Identify: actors, actions, data, constraints
    3. For unclear aspects:
       - Make informed guesses based on context and industry standards
       - Only mark with [NEEDS CLARIFICATION: specific question] if:
         - The choice significantly impacts feature scope or user experience
         - Multiple reasonable interpretations exist with different implications
         - No reasonable default exists
       - **LIMIT: Maximum 3 [NEEDS CLARIFICATION] markers total**
       - Prioritize clarifications by impact: scope > security/privacy > user experience > technical details
    4. Fill User Scenarios & Testing section
       If no clear user flow: ERROR "Cannot determine user scenarios"
       **Map each user story to relevant skills (0-N).**
    5. Generate Functional Requirements
       Each requirement must be testable
       Use reasonable defaults for unspecified details (document assumptions in Assumptions section)
    6. Define Success Criteria
       Create measurable, technology-agnostic outcomes
       Include both quantitative metrics (time, performance, volume) and qualitative measures (user satisfaction, task completion)
       Each criterion must be verifiable without implementation details
    7. Identify Key Entities (if data involved)
    8. Return: SUCCESS (spec ready for planning)

5. **Analyze Available Domain Skills**:

   Run the following command to get the list of domain skills available in this project:
   ```bash
   python3 .specify/scripts/resolve-skills.py --list-domain
   ```

   This returns only **domain skills** (skills without a `speckit-adapter.yaml`). These are user-defined, project-specific skills that must be actively discovered and used.

   - **DO NOT** include adapter-based skills (`speckit-architect`, `speckit-developer`, `speckit-tech-lead`, `speckit-librarian`, etc.) in the Available Skills Analysis — they are automatically injected at their respective phases and require no mention in the spec.
   - From the domain skills list, identify any that are **directly relevant** to this feature's requirements.
   - If **none** are relevant, write `None applicable` in the Available Skills Analysis section.
   - If a relevant skill is found, **READ its full `SKILL.md`** content. Look for "Constraints", "Requirements", "Workflow", or "Testing & Verification" sections and INJECT those requirements into `spec.md` under `Requirements` or `Success Criteria`.
   - **Constraint Injection example**: If skill says "Must run pipeline tests", add `SC-XXX: Passes pipeline tests` to Spec.

6. Write the specification to SPEC_FILE using the template structure:
   - Follow `.specify/templates/spec-template.md` perfectly.
   - Populate `## Available Skills Analysis` with your findings.
   - Replace placeholders with concrete details derived from the feature description.

7. **Specification Quality Validation**: After writing the initial spec, validate it against quality criteria:

   a. **Create Spec Quality Checklist**: Generate a checklist file at `FEATURE_DIR/checklists/requirements.md` using the checklist template structure with these validation items:

      ```markdown
      # Specification Quality Checklist: [FEATURE NAME]
      
      **Purpose**: Validate specification completeness and quality before proceeding to planning
      **Created**: [DATE]
      **Feature**: [Link to spec.md]
      
      ## Content Quality
      
      - [ ] No implementation details (languages, frameworks, APIs)
      - [ ] Focused on user value and business needs
      - [ ] Written for non-technical stakeholders
      - [ ] All mandatory sections completed
      
      ## Requirement Completeness
      
      - [ ] No [NEEDS CLARIFICATION] markers remain
      - [ ] Requirements are testable and unambiguous
      - [ ] Success criteria are measurable
      - [ ] Success criteria are technology-agnostic (no implementation details)
      - [ ] All acceptance scenarios are defined
      - [ ] Edge cases are identified
      - [ ] Scope is clearly bounded
      - [ ] Dependencies and assumptions identified
      
      ## Feature Readiness
      
      - [ ] All functional requirements have clear acceptance criteria
      - [ ] User scenarios cover primary flows
      - [ ] Feature meets measurable outcomes defined in Success Criteria
      - [ ] No implementation details leak into specification
      
      ## Notes
      
      - Items marked incomplete require spec updates before `/speckit.clarify` or `/speckit.plan`
      ```

   b. **Run Validation Check**: Review the spec against each checklist item:
      - For each item, determine if it passes or fails
      - Document specific issues found (quote relevant spec sections)

   c. **Handle Validation Results**:

      - **If all items pass**: Mark checklist complete and proceed to step 6

      - **If items fail (excluding [NEEDS CLARIFICATION])**:
        1. List the failing items and specific issues
        2. Update the spec to address each issue
        3. Re-run validation until all items pass (max 3 iterations)
        4. If still failing after 3 iterations, document remaining issues in checklist notes and warn user

      - **If [NEEDS CLARIFICATION] markers remain**:
        1. Extract all [NEEDS CLARIFICATION: ...] markers from the spec
        2. **LIMIT CHECK**: If more than 3 markers exist, keep only the 3 most critical (by scope/security/UX impact) and make informed guesses for the rest
        3. For each clarification needed (max 3), present options to user in this format:

           ```markdown
           ## Question [N]: [Topic]
           
           **Context**: [Quote relevant spec section]
           
           **What we need to know**: [Specific question from NEEDS CLARIFICATION marker]
           
           **Suggested Answers**:
           
           | Option | Answer | Implications |
           |--------|--------|--------------|
           | A      | [First suggested answer] | [What this means for the feature] |
           | B      | [Second suggested answer] | [What this means for the feature] |
           | C      | [Third suggested answer] | [What this means for the feature] |
           | Custom | Provide your own answer | [Explain how to provide custom input] |
           
           **Your choice**: _[Wait for user response]_
           ```

        4. **CRITICAL - Table Formatting**: Ensure markdown tables are properly formatted:
           - Use consistent spacing with pipes aligned
           - Each cell should have spaces around content: `| Content |` not `|Content|`
           - Header separator must have at least 3 dashes: `|--------|`
           - Test that the table renders correctly in markdown preview
        5. Number questions sequentially (Q1, Q2, Q3 - max 3 total)
        6. Present all questions together before waiting for responses
        7. Wait for user to respond with their choices for all questions (e.g., "Q1: A, Q2: Custom - [details], Q3: B")
        8. Update the spec by replacing each [NEEDS CLARIFICATION] marker with the user's selected or provided answer
        9. Re-run validation after all clarifications are resolved

   d. **Update Checklist**: After each validation iteration, update the checklist file with current pass/fail status

7. Report completion with branch name (including type prefix, e.g., `feat/001-user-auth`), branch type, spec file path, checklist results, and readiness for the next phase (`/speckit.clarify` or `/speckit.plan`).

**NOTE:** The script creates and checks out the new branch (with type prefix) and initializes the spec file before writing. Branch name format: `type/###-short-name`.

## General Guidelines

## Quick Guidelines

- Focus on **WHAT** users need and **WHY**.
- Avoid HOW to implement (no tech stack, APIs, code structure).
- Written for business stakeholders, not developers.
- DO NOT create any checklists that are embedded in the spec. That will be a separate command.

### Section Requirements

- **Mandatory sections**: Must be completed for every feature
- **Optional sections**: Include only when relevant to the feature
- When a section doesn't apply, remove it entirely (don't leave as "N/A")

### For AI Generation

When creating this spec from a user prompt:

1. **Make informed guesses**: Use context, industry standards, and common patterns to fill gaps
2. **Document assumptions**: Record reasonable defaults in the Assumptions section
3. **Limit clarifications**: Maximum 3 [NEEDS CLARIFICATION] markers - use only for critical decisions that:
   - Significantly impact feature scope or user experience
   - Have multiple reasonable interpretations with different implications
   - Lack any reasonable default
4. **Prioritize clarifications**: scope > security/privacy > user experience > technical details
5. **Think like a tester**: Every vague requirement should fail the "testable and unambiguous" checklist item
6. **Common areas needing clarification** (only if no reasonable default exists):
   - Feature scope and boundaries (include/exclude specific use cases)
   - User types and permissions (if multiple conflicting interpretations possible)
   - Security/compliance requirements (when legally/financially significant)

**Examples of reasonable defaults** (don't ask about these):

- Data retention: Industry-standard practices for the domain
- Performance targets: Standard web/mobile app expectations unless specified
- Error handling: User-friendly messages with appropriate fallbacks
- Authentication method: Standard session-based or OAuth2 for web apps
- Integration patterns: RESTful APIs unless specified otherwise

### Success Criteria Guidelines

Success criteria must be:

1. **Measurable**: Include specific metrics (time, percentage, count, rate)
2. **Technology-agnostic**: No mention of frameworks, languages, databases, or tools
3. **User-focused**: Describe outcomes from user/business perspective, not system internals
4. **Verifiable**: Can be tested/validated without knowing implementation details

**Good examples**:

- "Users can complete checkout in under 3 minutes"
- "System supports 10,000 concurrent users"
- "95% of searches return results in under 1 second"
- "Task completion rate improves by 40%"

**Bad examples** (implementation-focused):

- "API response time is under 200ms" (too technical, use "Users see results instantly")
- "Database can handle 1000 TPS" (implementation detail, use user-facing metric)
- "React components render efficiently" (framework-specific)
- "Redis cache hit rate above 80%" (technology-specific)
