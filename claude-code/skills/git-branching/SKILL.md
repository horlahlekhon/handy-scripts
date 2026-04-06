---
name: git-branching
description: Git branching strategy, naming conventions, rebase vs merge, squash guidance, PR sizing, and release branch patterns. Use when working with branches, PRs, or resolving conflicts.
origin: ECC
---

# Git Branching Strategy

Consistent branching practices for clean history, safe collaboration, and efficient code review.

## When to Activate

- Creating a new branch for a feature or fix
- Deciding how to merge or rebase a branch
- Resolving merge conflicts
- Sizing or structuring a pull request
- Setting up release or hotfix branches

## When NOT to Use This Skill

- Commit message formatting — see `rules/common/git-workflow.md`
- GitHub operations (PRs, issues, CI) — use the `github-ops` skill

## Branch Naming

Use a consistent prefix that describes the branch purpose:

| Prefix | Use for |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Maintenance, dependency updates, config |
| `refactor/` | Code restructuring with no behavior change |
| `docs/` | Documentation only |
| `hotfix/` | Urgent production fixes |

Format: `prefix/short-description-in-kebab-case`

Examples:
```
feat/user-auth-jwt
fix/cart-total-rounding
chore/upgrade-node-22
hotfix/payment-timeout-crash
```

## Branching Model

- Branch from `main` (or the default branch) for all work
- Never commit directly to `main`
- Keep feature branches short-lived — merge within days, not weeks
- One logical unit of work per branch; split if scope grows

## Rebase vs. Merge

| Situation | Use |
|-----------|-----|
| Cleaning up local commits before pushing | `git rebase -i main` |
| Staying up-to-date with main (before PR) | `git rebase main` |
| Integrating a shared/long-lived branch | `git merge` (preserves context) |
| Merging a PR into main | Squash merge (clean history) or merge commit (preserve commit trail) |

**Never rebase a branch that others have already pulled.** Rebase rewrites history — only use it on commits that haven't been shared.

## Squash Guidelines

**Squash** (combine all PR commits into one) when:
- The PR is a single logical unit (e.g., one feature, one bug fix)
- Individual commits are WIP checkpoints with no standalone value
- You want a clean, readable main branch history

**Do not squash** when:
- Multiple authors contributed to the branch (attribution is lost)
- Individual commits represent meaningful, reviewable milestones
- The PR is large and reviewers need commit context to understand changes

## PR Size

- Target **< 400 lines changed** per PR (excluding generated files, lock files)
- If a PR grows beyond 400 lines, split it:
  1. Extract prerequisite refactoring into a separate PR
  2. Build the feature on top of it
- Reviewers can't effectively review 1000-line diffs — smaller PRs get faster, better reviews

## Release Branches

For projects with scheduled releases:
```
main ──────────────────────────────── (always deployable)
          │
          └── release/1.2 ──────────── (stabilization: only bug fixes)
                    │
                    └── hotfix/1.2.1 ─ (emergency fix, merged back to main + release)
```

- Create `release/x.y` from `main` when feature freeze begins
- Only merge bug fixes into the release branch after freeze
- Tag the release commit: `git tag v1.2.0`
- Merge hotfixes back to both `main` and the active release branch

## Merge Conflicts

1. Always rebase onto `main` before resolving to minimize conflict scope
2. Resolve conflicts in the editor — never use `git checkout --ours/--theirs` blindly
3. After resolving: run tests before pushing
4. If conflicts are large and risky, consider breaking the PR into smaller pieces

## Done When

- Branch name follows the prefix convention
- PR diff is under ~400 lines (or justifiably larger with a note)
- Branch is rebased onto latest `main` before PR review
- Merge strategy (squash vs. merge commit) is consistent with project convention
- No direct commits to `main`; all changes go through a PR
