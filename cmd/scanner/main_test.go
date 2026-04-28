package main

import (
	"encoding/json"
	"strings"
	"testing"

	"sentinel-scanner/internal/analyzer"
)

func TestDetectAlpineVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
		sbom     []analyzer.Package
		want     string
		wantErr  bool
	}{
		{
			name:     "uses alpine-release from sbom",
			imageRef: "alpine:3.14",
			sbom: []analyzer.Package{
				{Name: "alpine-release", Version: "3.14.10-r0"},
				{Name: "musl", Version: "1.2.2-r4"},
			},
			want: "3.14",
		},
		{
			name:     "falls back to image tag major minor",
			imageRef: "alpine:3.18.6",
			sbom: []analyzer.Package{
				{Name: "musl", Version: "1.2.4-r0"},
			},
			want: "3.18",
		},
		{
			name:     "errors when alpine-release malformed",
			imageRef: "alpine:3.14",
			sbom: []analyzer.Package{
				{Name: "alpine-release", Version: "3"},
			},
			wantErr: true,
		},
		{
			name:     "errors when no sbom signal and unparseable tag",
			imageRef: "alpine:latest",
			sbom: []analyzer.Package{
				{Name: "busybox", Version: "1.36.1-r8"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := detectAlpineVersion(tc.imageRef, tc.sbom)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("detectAlpineVersion(%q, sbom) expected error, got nil", tc.imageRef)
				}
				return
			}

			if err != nil {
				t.Fatalf("detectAlpineVersion(%q, sbom) unexpected error: %v", tc.imageRef, err)
			}
			if got != tc.want {
				t.Fatalf("detectAlpineVersion(%q, sbom) = %q, want %q", tc.imageRef, got, tc.want)
			}
		})
	}
}

func TestCalculateRiskScoreAndSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cveCount   int
		wantScore  int
		wantSev    string
		scoreRange bool
	}{
		{
			name:      "zero cves yields none",
			cveCount:  0,
			wantScore: 0,
			wantSev:   "NONE",
		},
		{
			name:       "single cve yields low",
			cveCount:   1,
			wantSev:    "LOW",
			scoreRange: true,
		},
		{
			name:       "several cves yields high",
			cveCount:   4,
			wantSev:    "HIGH",
			scoreRange: true,
		},
		{
			name:       "many cves yields critical",
			cveCount:   8,
			wantSev:    "CRITICAL",
			scoreRange: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotScore := calculateRiskScore(tc.cveCount)
			if tc.scoreRange {
				if gotScore <= 0 || gotScore > 100 {
					t.Fatalf("calculateRiskScore(%d) = %d, expected range (0,100]", tc.cveCount, gotScore)
				}
			} else if gotScore != tc.wantScore {
				t.Fatalf("calculateRiskScore(%d) = %d, want %d", tc.cveCount, gotScore, tc.wantScore)
			}

			gotSeverity := classifySeverity(gotScore)
			if gotSeverity != tc.wantSev {
				t.Fatalf("classifySeverity(%d) = %q, want %q", gotScore, gotSeverity, tc.wantSev)
			}
		})
	}
}

func TestBuildRemediation(t *testing.T) {
	t.Parallel()

	got := buildRemediation("musl", "1.2.2-r6")
	if !strings.Contains(got, "musl") {
		t.Fatalf("remediation should include package name, got: %s", got)
	}
	if !strings.Contains(got, "1.2.2-r6") {
		t.Fatalf("remediation should include fix version, got: %s", got)
	}
}

func TestHighestSeverity(t *testing.T) {
	t.Parallel()

	findings := []PackageFinding{
		{PackageName: "a", RiskScore: 30},
		{PackageName: "b", RiskScore: 72},
		{PackageName: "c", RiskScore: 95},
	}

	got := highestSeverity(findings)
	if got != "CRITICAL" {
		t.Fatalf("highestSeverity(findings) = %q, want %q", got, "CRITICAL")
	}
}

func TestNormalizeFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "text", want: "text"},
		{input: "json", want: "json"},
		{input: " JSON ", want: "json"},
		{input: "table", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeFormat(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeFormat(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeFormat(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeFormat(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeSeverityThresholdAndFailPolicy(t *testing.T) {
	t.Parallel()

	threshold, err := normalizeSeverityThreshold("high")
	if err != nil {
		t.Fatalf("normalizeSeverityThreshold(high) unexpected error: %v", err)
	}
	if threshold != "HIGH" {
		t.Fatalf("normalizeSeverityThreshold(high) = %q, want HIGH", threshold)
	}

	if !shouldFailBuild("CRITICAL", "HIGH") {
		t.Fatalf("shouldFailBuild should fail when highest >= threshold")
	}
	if shouldFailBuild("LOW", "HIGH") {
		t.Fatalf("shouldFailBuild should not fail when highest < threshold")
	}
	if shouldFailBuild("CRITICAL", "NONE") {
		t.Fatalf("shouldFailBuild should not fail for NONE threshold")
	}

	if _, err := normalizeSeverityThreshold("severe"); err == nil {
		t.Fatalf("normalizeSeverityThreshold(severe) expected error, got nil")
	}
}

func TestScanReportJSONShape(t *testing.T) {
	t.Parallel()

	report := ScanReport{
		TargetImage: "alpine:3.14",
		Findings: []PackageFinding{
			{
				PackageName:      "musl",
				InstalledVersion: "1.2.2-r4",
				EarliestFix:      "1.2.2_pre2-r0",
				CVEs:             []string{"CVE-2020-28928"},
				RiskScore:        30,
				Severity:         "LOW",
				Remediation:      "Upgrade musl to version 1.2.2_pre2-r0 or newer, then rebuild and redeploy the image.",
			},
		},
		Context: ScanContext{
			ScannedAtUTC:       "2026-04-28T18:24:20Z",
			InstalledPackages:  14,
			SecDBPackages:      462,
			MatchedPackages:    5,
			VulnerablePackages: 1,
			UniqueCVEs:         1,
			HighestSeverity:    "LOW",
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal(report) unexpected error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(report) unexpected error: %v", err)
	}

	if decoded["targetImage"] != "alpine:3.14" {
		t.Fatalf("targetImage mismatch: got %#v", decoded["targetImage"])
	}
	if _, ok := decoded["findings"]; !ok {
		t.Fatalf("expected findings key in JSON output")
	}
	if _, ok := decoded["context"]; !ok {
		t.Fatalf("expected context key in JSON output")
	}
}
