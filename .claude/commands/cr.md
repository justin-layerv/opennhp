---
name: cr
description: Process code review feedback on a PR
---

Critically analyze the code review feedback on this PR: $ARGUMENTS

## Instructions

1. Fetch the PR, read the code review comments, and check out the PR branch locally to understand the code changes in context
   - **IMPORTANT**: Always start with the LATEST/most recent review comments (sorted by date) - PRs may have multiple rounds of feedback
   - Review ALL feedback including: required fixes, suggestions, recommendations, and "nice-to-have" improvements
   - Don't overlook items labeled as "minor suggestions" or "considerations" - these must still be evaluated
2. For each piece of feedback, determine if it should be:
   - **Fixed now**: Makes sense, improves the code, reasonable effort
   - **Deferred**: Out of scope, requires significant refactoring, or disagree with the suggestion

3. Before making any changes, show me:
   - A summary of what you plan to fix
   - A list of what you plan to defer (with brief reasoning for each deferral)

4. Wait for my approval on the deferral list. I may ask you to fix one or more of the deferred items.

5. After I approve:
   - Implement the agreed fixes
   - Commit (following conventional commit format) and push the changes to the PR branch
   - Comment on the PR summarizing what was addressed and what was deferred (with reasoning)
   - Update the PR description if the changes warrant it
