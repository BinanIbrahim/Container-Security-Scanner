# Sentinel Scanner — Roadmap

Living document. Tick items off as they land; reorder when priorities change.

## Phase 1 — Correctness & Robustness (foundation)

- [x] **Real APK version comparison parity.** Current tokenizer in `internal/matcher/version.go` misses APK suffix semantics (`_alpha`, `_beta`, `_rc`, `_pre`, `_p`, `_git`). E.g. `1.2.2_pre2` should rank lower than `1.2.2`. Port logic from `apk-tools` `apk_version.c` and add a golden-file test suite.
- [x] **Bounded tar extraction.** `internal/extractor/extractor.go` does unbounded `io.Copy` — malicious layer can fill disk (tar bomb). Wrap in `io.LimitReader` with configurable cap and reject symlinks/hardlinks pointing outside target.
- [ ] **Stream layers instead of extracting to disk.** Today we untar the whole image then walk layers again. Read layers directly from the saved tar stream — faster, lower disk footprint, removes temp dir need for most scans.
- [ ] **SecDB caching.** On-disk cache keyed by `(version, repo, ETag/Last-Modified)` under `$XDG_CACHE_HOME/sentinel`. Adds offline support and cuts repeated network calls in CI.
- [ ] **Context + cancellation.** Plumb `context.Context` through `extractor`, `analyzer`, `matcher`. A hung `docker pull` is currently unkillable.

## Phase 2 — Coverage & Accuracy

- [ ] **CVSS scores from NVD/OSV.** Current severity derived from CVE *count* — inverts reality (one CRITICAL RCE scores LOW, ten LOW infoleaks score HIGH). Map each CVE to NVD CVSS v3 score; use max-severity per package as the real signal. Keep `riskScore` as aggregate but base on CVSS.
- [ ] **Multi-distro support.** Abstract `analyzer` behind a `DistroAdapter` interface (`DetectVersion`, `ParsePackageDB`, `SecDBURL`). Add Debian/Ubuntu (dpkg + Debian Security Tracker) and RHEL/UBI (rpm + RHSA OVAL).
- [ ] **Language-level SBOM.** Detect `node_modules/`, `*.gemspec`, `go.mod`, `requirements.txt`, `Cargo.lock` inside layers. Match against OSV.dev (single API, covers all ecosystems).
- [ ] **Image config inspection.** Parse image config blob to flag misconfigurations: `USER 0`/root, exposed sensitive ports, `latest` base tag, missing `HEALTHCHECK`.

## Phase 3 — UX & Integration

- [ ] **SARIF output** (`--format sarif`) so GitHub Code Scanning ingests results natively.
- [ ] **`.sentinelignore`** for suppressing specific CVE/package pairs with justification + expiry.
- [ ] **Daemonless mode.** Replace `docker save` with direct registry pulls via `github.com/google/go-containerregistry`. Removes Docker daemon requirement — huge for CI runners.
- [ ] **Structured logging** via `log/slog` with `--verbose`/`--quiet` instead of the current `textOutput` bool threaded through every package.
- [ ] **Single `Scanner` struct.** `cmd/scanner/main.go` is currently a 350-line `func main`. Extract `scan.Run(cfg) (Report, error)` so CLI is a thin wrapper and scanner becomes embeddable as a library.

## Phase 4 — Project Hygiene

- [x] **CI pipeline** (GitHub Actions): `go vet`, `go test -race -cover`, `golangci-lint`, `govulncheck`, build matrix for linux/darwin amd64+arm64.
- [ ] **Release automation** with `goreleaser` → signed binaries + multi-arch container image.
- [ ] **Integration tests** that scan a curated set of pinned images (`alpine:3.14`, `alpine:3.19`, a known-clean image, a known-vulnerable image) and assert findings.

## Recommended Order

Phase 1 → Phase 2 #1 (CVSS) → Phase 3 #3 & #5 (daemonless + library refactor) → everything else.

The highest-leverage items are Phase 1 #1, Phase 2 #1, and Phase 3 #3 — they unlock real-world usefulness. The rest is breadth on top of a correct core.
