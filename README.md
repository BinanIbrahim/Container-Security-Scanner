# Sentinel Scanner

Sentinel Scanner is a CLI tool that scans Alpine-based Docker images for known vulnerabilities.

It builds a lightweight SBOM from image layers, detects the Alpine OS version, fetches Alpine SecDB data, and reports vulnerable packages with CVE IDs.

## Features

- Scans Docker images from the command line (`--image`).
- Extracts and analyzes image layers to build an SBOM.
- Detects Alpine version from `alpine-release` (with safe fallback to image tag parsing).
- Fetches and merges Alpine SecDB from both:
  - `main`
  - `community`
- Uses APK-aware version comparison (better than plain string comparison).
- Deduplicates findings by package and CVE.
- Adds package-level severity scoring (LOW to CRITICAL) based on finding breadth.
- Prints remediation suggestions for each vulnerable package.
- Prints scan context metrics for confidence and debugging.

## Current Scope

- Alpine images only.
- Data source: Alpine Security Database (SecDB).
- Requires Docker installed and running.

## Project Structure

- `cmd/scanner/main.go`: CLI entrypoint and scan/report orchestration.
- `internal/extractor/`: pulls, saves, and unpacks Docker images.
- `internal/analyzer/`: reads manifest/layers and builds SBOM from Alpine package DB.
- `internal/matcher/`: fetches SecDB, compares versions, and drives vulnerability matching helpers.

## Requirements

- Go `1.26.1` (as defined in `go.mod`)
- Docker CLI + Docker daemon
- Network access to `secdb.alpinelinux.org`

## Quick Start

```bash
go run cmd/scanner/main.go --image alpine:3.14
```

## Example Output

```text
=== SENTINEL CONTAINER SCANNER ===
Target: alpine:3.14
...
=== VULNERABILITY REPORT ===
[!] VULNERABILITY FOUND: musl
    - Installed Version : 1.2.2-r4
    - Earliest Fix In   : 1.2.2_pre2-r0
    - Severity          : LOW (score: 30/100)
    - CVEs              : CVE-2020-28928
    - Remediation       : Upgrade musl to version 1.2.2_pre2-r0 or newer, then rebuild and redeploy the image.

[!] Scan complete. 1 unique CVE findings detected.

=== SCAN CONTEXT ===
    - Scanned At (UTC)        : 2026-04-26T13:10:23Z
    - Installed Packages      : 14
    - SecDB Packages Loaded   : 462
    - Packages Matched In DB  : 5
    - Vulnerable Packages     : 1
    - Unique CVE Findings     : 1
    - Highest Severity        : LOW
```

## Run Tests

```bash
go test ./...
```

## Notes

- Vulnerability results depend on the current SecDB snapshot at scan time.
- Older image tags can still receive newly published CVEs as advisory data evolves.

## Roadmap Ideas

- JSON output mode for CI pipelines.
- Severity grouping in report output.
- Support for additional Linux distributions.
