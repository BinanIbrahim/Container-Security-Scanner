# Sentinel Scanner

Sentinel Scanner is a **zero-dependency** **CLI** tool written in **Go** that
scans **Alpine**-based **Docker images** for known security **vulnerabilities** —
before they ship to production.

Container images bundle dozens of **OS packages**, and any one of them can carry
a published **CVE**. Tracking that by hand is impractical: you would have to know
every package and version baked into an image, cross-reference each against an
ever-changing **vulnerability feed**, and understand **Alpine's APK versioning**
rules to tell whether an installed version is actually older than the one that
fixes a given CVE. Sentinel automates exactly that loop.

Point it at an image and it works as a **pipeline**: it pulls and unpacks the
image, reads the **Alpine package database** out of the layers to build a
lightweight **SBOM** (software bill of materials), detects the Alpine OS version,
downloads the matching **Alpine Security Database (SecDB)**, and compares every
installed package against the known fixes using an **APK-aware version
comparator**. The result is a clear report of vulnerable packages with their
**CVE IDs**, a **severity score**, and concrete **remediation** guidance —
printed for humans or emitted as **JSON** with a configurable failure threshold
so it can **gate a CI pipeline**. It ships as a single **static binary** and
pulls in **no third-party dependencies**.

## Features

- Scans **Docker images** from the command line (`--image`).
- Machine-readable **JSON output** for **CI pipelines** (`--format json`).
- **Policy-based build failure** thresholds (`--fail-on`).
- Extracts and analyzes **image layers** to build an **SBOM**.
- Detects the Alpine version from `alpine-release` (with safe fallback to image-tag parsing).
- Fetches and merges **Alpine SecDB** from both the `main` and `community` repositories.
- **APK-aware version comparison**, including pre/post-release suffix semantics (see below).
- **Deduplicates** findings by package and CVE.
- Package-level **severity scoring** (LOW to CRITICAL) and per-package **remediation** hints.
- Prints **scan-context metrics** for confidence and debugging.

## Architecture

The scanner runs as a linear **pipeline**. Each stage hands its output to the
next, and the whole thing is orchestrated by `cmd/scanner/main.go`.

```
  --image alpine:3.14
        │
        ▼
┌───────────────────┐
│  docker pull      │   ensure the image exists locally
│  docker save      │   export it to image.tar          ── internal/extractor
│  unpack tarball   │   untar into a temp dir (zip-slip guarded)
└─────────┬─────────┘
          │  unpacked image (manifest.json + layer tarballs)
          ▼
┌───────────────────┐
│  read manifest    │   ordered list of layers
│  walk each layer  │   gzip/plain auto-detected         ── internal/analyzer
│  parse apk DB     │   lib/apk/db/installed → SBOM
└─────────┬─────────┘
          │  SBOM: []{name, version}
          ▼
┌───────────────────┐
│  detect version   │   alpine-release → v3.14
│  fetch SecDB      │   main.json + community.json        ── internal/matcher
│  merge + index    │   map[pkg] → secfixes
└─────────┬─────────┘
          │  vulnerability database
          ▼
┌───────────────────┐
│  match versions   │   installed < fixed ?  (apk-aware)
│  score severity   │   risk score → LOW…CRITICAL         ── cmd/scanner
│  render report    │   text or JSON, apply --fail-on
└─────────┬─────────┘
          ▼
   report + exit code
```

Pipeline in one line:

```
docker pull → docker save → unpack → SBOM → SecDB → match → report
```

### Project structure

- `cmd/scanner/main.go` — **CLI entrypoint**, matching loop, scoring, and report rendering.
- `internal/extractor/` — pulls, saves, and unpacks **Docker images**.
- `internal/analyzer/` — reads the manifest, walks layers, and builds the **SBOM** from the Alpine package DB.
- `internal/matcher/` — fetches/merges **SecDB** and provides the **apk-aware version comparison**.

## Why a custom APK version comparator?

Deciding whether an installed package is vulnerable comes down to a single
question: *is the installed version older than the version that fixes the CVE?*
That comparison is the **correctness core** of the whole tool — get it wrong and
the scanner silently produces **false negatives** (missed vulnerabilities) or
**false positives**. So we implemented it ourselves, in
[`internal/matcher/version.go`](internal/matcher/version.go), rather than pulling
in a dependency. Three reasons:

1. **Apk versions are not semver.** Alpine versions carry pre-release suffixes
   (`_alpha`, `_beta`, `_pre`, `_rc`), post-release suffixes (`_cvs`, `_svn`,
   `_git`, `_hg`, `_p`), and a build revision (`-rN`). The ordering is
   `1.2_pre1 < 1.2 < 1.2_p1`. General-purpose **semver libraries**
   (`Masterminds/semver`, `hashicorp/go-version`, …) implement the semver spec,
   which has no notion of these suffixes — they would parse `1.2.2_pre2` as
   garbage or rank it *above* `1.2.2`, inverting the result on exactly the
   tricky cases that matter.

2. **The canonical implementation is C.** The authoritative ordering lives in
   apk-tools' **`apk_version.c`**. Porting its **token-based comparison** directly
   (≈200 lines of pure Go, no allocations of note) is smaller and more auditable
   than wrapping **cgo** or adopting a heavyweight third-party port.

3. **Owning it lets us test it exhaustively, with zero supply-chain risk.** The
   comparator is **pure logic**, so it is backed by a **table-driven** test plus a
   **canonical 17-element ordering chain** checked all-pairs in both directions.
   For a security tool, keeping `go.mod` free of third-party dependencies is itself
   a feature (see [CONVENTIONS.md](CONVENTIONS.md)) — there is **no transitive
   dependency** to audit, pin, or trust.

> **Known limitation:** numeric components are compared as integers, so apk's
> leading-zero fractional rule (`1.07` vs `1.1`) is not reproduced. SecDB package
> versions do not rely on it.

## Requirements

- **Go `1.26.1`** (as defined in [go.mod](go.mod))
- **Docker CLI** + a running **Docker daemon**
- Network access to `secdb.alpinelinux.org`

## Quick Start

```bash
go run cmd/scanner/main.go --image alpine:3.14
```

CI-style run (JSON output + fail policy):

```bash
go run cmd/scanner/main.go --image alpine:3.14 --format json --fail-on high
```

Build a standalone binary:

```bash
go build -o sentinel ./cmd/scanner
./sentinel --image alpine:3.14
```

## Example Output

A real scan of `alpine:3.14`. The current image is fully patched — five of its
packages have SecDB advisories, but every one is already at or above the fixed
version, so nothing is flagged:

```text
=== SENTINEL CONTAINER SCANNER ===
Target: alpine:3.14

[*] Phase 1: Extracting Image...
Pulling and saving image 'alpine:3.14' (this might take a moment)...
Pulling image 'alpine:3.14' from registry...
Unpacking image layers...
[*] Phase 2: Analyzing Layers...
Found Alpine package database in layer: blobs/sha256/422ed46b1a92...
    -> Generated SBOM with 14 installed packages.
[*] Phase 3: Vulnerability Matching...
    -> Detected Alpine OS Version: v3.14
    -> Loaded 462 packages from Alpine SecDB.

=== VULNERABILITY REPORT ===
[✓] No known vulnerabilities found! Your image is clean.

=== SCAN CONTEXT ===
    - Scanned At (UTC)        : 2026-06-19T15:13:58Z
    - Installed Packages      : 14
    - SecDB Packages Loaded   : 462
    - Packages Matched In DB  : 5
    - Vulnerable Packages     : 0
    - Unique CVE Findings     : 0
    - Highest Severity        : NONE
```

Scanning an older, end-of-life tag surfaces real findings. Here `alpine:3.10`
reports a vulnerable `apk-tools` with its CVE, severity, and remediation:

```text
=== SENTINEL CONTAINER SCANNER ===
Target: alpine:3.10

[*] Phase 1: Extracting Image...
Pulling and saving image 'alpine:3.10' (this might take a moment)...
Pulling image 'alpine:3.10' from registry...
Unpacking image layers...
[*] Phase 2: Analyzing Layers...
Found Alpine package database in layer: blobs/sha256/26d14edc4f17...
    -> Generated SBOM with 14 installed packages.
[*] Phase 3: Vulnerability Matching...
    -> Detected Alpine OS Version: v3.10
    -> Loaded 285 packages from Alpine SecDB.

=== VULNERABILITY REPORT ===
[!] VULNERABILITY FOUND: apk-tools
    - Installed Version : 2.10.6-r0
    - Earliest Fix In   : 2.10.7-r0
    - Severity          : LOW (score: 30/100)
    - CVEs              : CVE-2021-36159
    - Remediation       : Upgrade apk-tools to version 2.10.7-r0 or newer, then rebuild and redeploy the image.

[!] Scan complete. 1 unique CVE findings detected.

=== SCAN CONTEXT ===
    - Scanned At (UTC)        : 2026-06-19T15:16:33Z
    - Installed Packages      : 14
    - SecDB Packages Loaded   : 285
    - Packages Matched In DB  : 3
    - Vulnerable Packages     : 1
    - Unique CVE Findings     : 1
    - Highest Severity        : LOW
```

## Output and Policy Flags

- `--format text|json` (default: `text`)
- `--fail-on none|low|medium|high|critical` (default: `none`)

`--fail-on` makes the scanner exit non-zero when the highest finding severity
meets or exceeds the threshold — use it to **gate a build or pipeline**.

### Exit codes

| Code | Meaning                                                     |
|------|-------------------------------------------------------------|
| `0`  | Scan completed; no `--fail-on` threshold met.               |
| `1`  | Usage or runtime error (bad flag, extraction/network fail). |
| `2`  | Scan completed but the `--fail-on` threshold was triggered. |

## Known Limitations

These are deliberate boundaries of the current scope, not accidental gaps. Several
are tracked as roadmap items in [ROADMAP.md](ROADMAP.md).

- **Alpine only.** Detection and the SecDB source are Alpine-specific. Debian/Ubuntu
  (dpkg) and RHEL/UBI (rpm) are planned behind a `DistroAdapter` interface but not
  implemented.
- **Static layer scan, not runtime.** The scanner reads the apk database baked into
  the image layers. It does **not** inspect a running container, observe processes,
  or catch packages installed at runtime (e.g. an `apk add` in an entrypoint).
- **OS packages only.** It matches the Alpine package database. Language-level
  dependencies (`node_modules`, `go.mod`, `requirements.txt`, …) are not yet scanned.
- **Severity is derived from CVE count, not CVSS.** A package with one critical RCE
  can currently score lower than one with several low-impact issues. Real CVSS
  scoring (via NVD/OSV) is the top Phase 2 roadmap item.
- **Requires the Docker daemon.** Images are obtained via `docker pull`/`docker save`.
  Daemonless registry pulls are planned.
- **Results track the live SecDB snapshot.** Findings can change over time as
  advisory data evolves, even for a fixed image tag.

## Run Tests

```bash
go test -race ./...
```

## Contributing

Development conventions (package boundaries, error handling, testing, the
zero-dependency policy) are documented in [CONVENTIONS.md](CONVENTIONS.md), and
planned work is tracked in [ROADMAP.md](ROADMAP.md).
