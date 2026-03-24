# Agent Skills Configuration

You have access to a library of specialized skills defined in this workspace. These skills provide specific workflows, instructions, and strategies for complex tasks.

## Core Directive

**You MUST prioritize using these skills over your general knowledge whenever they are relevant to the user's request.** Skills represent the "gold standard" for how tasks should be performed in this project.

## Skill Usage Protocol

1.  **Discovery**: When you receive a task, first check the `<available_skills>` list below.
2.  **Activation**: If a skill's `<description>` matches the task or seems relevant, you **MUST** read the skill definition file at the provided `<location>`.
3.  **Execution**: Follow the instructions in the skill file. Prioritize the skill's specific strategies over your general knowledge.

## Available Skills

{SKILLS_LIST}
