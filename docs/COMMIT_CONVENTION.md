# Commit Convention (Release Please)

This repository uses [Release Please](https://github.com/googleapis/release-please) for automated releases. Commits **must** follow [Conventional Commits](https://www.conventionalcommits.org/) format.

## Format

```
type(scope): description

[optional body]

[optional footer(s)]
```

## Commit Types and Version Impact

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | **Minor** (0.X.0) |
| `fix` | Bug fix | **Patch** (0.0.X) |
| `docs` | Documentation only | None |
| `style` | Code style (formatting, semicolons) | None |
| `refactor` | Code change that neither fixes nor adds | None |
| `perf` | Performance improvement | **Patch** |
| `test` | Adding or updating tests | None |
| `build` | Build system or dependencies | None |
| `ci` | CI configuration | None |
| `chore` | Maintenance tasks | None |

## Breaking Changes (Major Version)

Use `!` after the type or add `BREAKING CHANGE:` in the footer:

```bash
feat(api)!: remove deprecated endpoints

# Or with footer:
feat(api): redesign authentication flow

BREAKING CHANGE: JWT tokens now require audience claim
```

## Scopes

The canonical Scopes table lives in top-level `CLAUDE.md` under `### Scopes`
(the `scripts/check-scope-drift.sh` lint parses that exact heading at CI to
enforce parity with the Component dropdown in
`.github/ISSUE_TEMPLATE/bug_report.yml`). Add new scopes in `CLAUDE.md` and
the bug-report form in the same PR.

## Examples

```bash
feat(ac): add IPv6 support for iptables rules
fix(server): prevent panic on nil knock packet
docs(readme): update installation instructions
refactor(nhp): extract crypto utilities to separate package
feat(api)!: require authentication for all plugin endpoints
chore: sync with upstream OpenNHP
```

## Release Please Behavior

1. **On merge to main**: Release Please creates/updates a release PR
2. **Release PR**: Accumulates changes, updates CHANGELOG.md, bumps version
3. **Merge release PR**: Creates GitHub release with tag and artifacts
