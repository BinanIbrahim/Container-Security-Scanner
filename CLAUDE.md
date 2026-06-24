# Sentinel Scanner — Development Conventions

Rules that apply to every change in this repo. Treat this like a contract: if a PR breaks one of these, either fix the PR or update this document explicitly with a rationale.

## Common Commands

```bash
go build ./...                        # build
go test -race ./...                   # run all tests with race detector
go test -race -run TestName ./...     # run a single test
golangci-lint run                     # lint (must match CI: v2.12.2)
govulncheck ./...                     # vulnerability scan
```

## Code

- **Package boundaries match domain verbs**, not technical layers: `extractor`, `analyzer`, `matcher`. Do not add `utils`, `common`, `helpers`. If something doesn't fit an existing package, create a new domain-named one.
- **Errors wrap with context**: `fmt.Errorf("parse manifest: %w", err)`. Never `errors.New` at a call site that already has actionable context.
- **No `log.Fatal` outside `main`.** Library code returns errors. Only the CLI entrypoint decides to exit.
- **Exported = documented.** Every exported identifier gets a `// Name ...` godoc comment. Unexported code stays uncommented unless the *why* is non-obvious.
- **Context first, options last.** Function signatures: `func Foo(ctx context.Context, required..., opts Options) (Result, error)`.
- **Severity, format, and threshold are types**, not strings. Define `type Severity int` with `iota` constants and a `String()` method — kills the repeated `strings.ToUpper` normalization.
- **No `interface{}` / `any` in public APIs.** If you reach for it, you're missing a type.

## Testing

- **Table-driven tests** for everything pure (version comparison, severity classification, threshold logic). One `t.Run(tc.name, ...)` per case.
- **No network in unit tests.** `matcher.FetchSecDB` tests use `httptest.Server`. Keep it that way.
- **Golden files** for end-to-end report output. Update via `-update` flag, never by hand.
- **Race detector on by default**: `go test -race ./...` runs in CI.
- **No `time.Sleep` in tests.** If you need to wait for something, the code under test needs a synchronization primitive, not a delay.

## Git & PRs

- **Imperative subject, ≤72 chars**: "Add CVSS lookup via NVD" — matches existing log style.
- **One logical change per commit.** No "fix typo + add feature" commits.
- **PR description = why, not what.** The diff shows what.
- **No force-push to `main`.** Feature branches squash-merge.

## Tooling (enforced in CI, not by humans)

- `gofmt -s` + `goimports`
- `golangci-lint` with `errcheck`, `govet`, `staticcheck`, `revive`, `gosec`
- `govulncheck` on every PR — dogfood the goal
- Minimum coverage gate (start at 60%, raise as Phase 1 lands)

## Dependencies

- **Justify every new dep in the PR description.** Standard library first. Current `go.mod` has zero third-party deps — that's a feature worth defending until something like multi-distro support forces it.
- **Pin Go toolchain** in `go.mod`; bump deliberately, not opportunistically.

## Agents

- **Before every push to GitHub**, run a code-reviewer agent on the changed files: "Use the code-reviewer agent to review the changes on this branch before I push." Do not push until the review passes or findings are explicitly accepted by the user.
- **Before starting any new feature from `ROADMAP.md`**, spawn a Plan agent: "Use a Plan agent to design [feature name] based on the roadmap." The plan must be approved by the user before any code is written.

## Feature Briefing

- **Before starting any feature**, write a short plain-English brief to the user covering three things: (1) what we are building, (2) why we are building it (the problem it solves), and (3) how it benefits the project or the user. Two to four sentences is enough — no headers, no bullet walls. Wait for the user to acknowledge before spawning the Plan agent or writing any code.

## Working With These Docs

- `ROADMAP.md` is the source of truth for what to build next. Pick the topmost unchecked item in the current phase unless the user redirects.
- `CLAUDE.md` (this file) applies to *every* change. Updates to it require an explicit user request — do not silently change the rules.
- When you finish a roadmap item, tick the checkbox in the same commit that lands the change.
