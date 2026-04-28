package main

import (
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
