---
name: pr-ready
description: Use when a change on a netop branch is done and needs to become a pull request - runs every CI gate locally (gofmt, vet, race tests, the cross-build matrix), commits, pushes, opens the PR with the flags this repo's redirected remote requires, then runs the CLAUDE.md self-review.
disable-model-invocation: true
---

# pr-ready

Turn a finished branch into a reviewed pull request without a red CI check or a failed `gh pr create`.

## Steps

0. **Confirm there is something to ship.** `git status --short` and `git log --oneline master..HEAD`. If both are empty, stop and say so.

1. **Preflight.** Run `.claude/skills/pr-ready/scripts/preflight.sh`. It runs the gates from `.github/workflows/build.yml` (gofmt, `go vet`, `go test -race`, the five-target cross-build matrix) plus `go vet -tags integration`, which CI does not run but which catches broken integration test files. Fix everything it reports. `--quick` skips the race tests for iteration; the run immediately before any push must be a full run. CI uses the Go version pinned in build.yml, so a newer local toolchain can still differ on gofmt output.

2. **Commit with explicit paths.** `git add <files>`, never `git add -A`, and check `git status --short` for stray files first. Message: `type(scope): summary` (match `git log --oneline`), a body saying why, then the `Co-Authored-By: Claude ... <noreply@anthropic.com>` trailer plus any other trailer the session specifies.

3. **Push.** `git push -u origin <branch>`.

4. **Open the PR with explicit flags.** `origin` points at `XpertaDK/netop`, which redirects to `AngelFreak/netop`. A plain `gh pr create` fails with `Head sha can't be blank`. Always:

   ```bash
   gh pr create --repo XpertaDK/netop --base master --head <branch> --title "type(scope): summary" --body "..."
   N=$(gh pr view <branch> --repo AngelFreak/netop --json number -q .number)
   ```

   Title uses the same `type(scope):` form as the commit. Body: what changed, why, how it was verified, ending with `🤖 Generated with [Claude Code](https://claude.com/claude-code)` and the session link when one is given. Reference the PR with `--repo AngelFreak/netop` from here on.

5. **Self-review.** `gh pr diff $N --repo AngelFreak/netop` and check for: dead code or no-op implementations, helpers that duplicate stdlib, deprecated calls, missing imports after refactors, inconsistent error handling, package-level mutable state. For anything found: fix, full preflight, commit, push, repeat this step. The PR is ready only when a pass finds nothing.

6. **Confirm CI started.** `gh pr checks $N --repo AngelFreak/netop`.

## Common mistakes

| Mistake | Consequence |
|---|---|
| Skipping the darwin build | `pkg/network` and `pkg/wgconfig` need `!linux` stubs; only the darwin target catches a missing one |
| Skipping `go vet -tags integration` | Integration test files are invisible to plain vet and break silently |
| `gh pr create` without `--repo/--base/--head` | `Head sha can't be blank` |
| Running preflight on `master` | The script refuses; branch first |
| Pushing a follow-up after a `--quick` run only | Race failures surface in CI instead of locally |
