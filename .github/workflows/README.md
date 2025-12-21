# Changelog Generation Workflow

This document explains the automatic changelog generation workflow for the print-queue project.

## Overview

The repository includes a GitHub Action that automatically generates a changelog section when a pull request from the `qa` branch is merged into the `main` branch.

## Workflow Location

`.github/workflows/changelog.yml`

## Trigger Conditions

The workflow triggers when:
- A pull request is closed
- The pull request was merged (not just closed)
- The base branch is `main`
- The head branch is `qa`

## What It Does

When a QA → main merge occurs, the workflow:

1. **Analyzes Commits**: Collects all non-merge commits between the previous QA → main merge and the current one
2. **Generates Changelog**: Creates a new changelog file with the structure defined in `VERSIONING.md`:
   - Overview / Highlights
   - Enhancements
   - Bug Fixes
   - Notes / Things to Know
3. **Posts Comment**: Adds a comment to the PR with the generated changelog
4. **Commits File**: Commits the changelog file to the main branch

## Changelog Structure

The generated changelog follows the format specified in `VERSIONING.md`:

```markdown
# Changelog - Version TBD

## Overview / Highlights
<!-- High-level summary of what changed -->

## Enhancements
<!-- New features, UX improvements, performance improvements -->
- Commit message 1
- Commit message 2
...

## Bug Fixes
<!-- Fixed defects, stability improvements, regression fixes -->

## Notes / Things to Know
<!-- Behavioral changes, migration steps, configuration changes -->
```

## Post-Generation Steps

After the changelog is generated, you should:

1. **Review the changelog file** in the repository (named `CHANGELOG_YYYYMMDD_HHMMSS.md`)
2. **Organize commits** into the appropriate sections (Enhancements, Bug Fixes, Notes)
3. **Add a version number** according to the versioning scheme in `VERSIONING.md`
4. **Update the Overview/Highlights** section with a high-level summary
5. **Clean up commit messages** for clarity and readability

## Example Workflow

1. Develop features in a feature branch
2. Merge feature branch to `qa` for testing
3. After QA validation, create a PR from `qa` to `main`
4. When the PR is merged:
   - The changelog workflow automatically runs
   - A new changelog file is created and committed to `main`
   - A comment appears on the PR with the generated changelog
5. Review and refine the changelog as needed

## Permissions

The workflow requires:
- `contents: write` - To commit the changelog file to the repository
- `pull-requests: write` - To post comments on the pull request

## Notes

- The workflow uses the standard GitHub Actions bot credentials
- Changelog files are timestamped to avoid conflicts
- All commit messages from the merge are initially placed in the Enhancements section
- You'll need to manually reorganize them into the correct sections

## Troubleshooting

If the workflow doesn't run:
1. Ensure the PR is from `qa` to `main`
2. Ensure the PR was merged (not just closed)
3. Check the Actions tab for any workflow errors
4. Verify the workflow has the necessary permissions
