package main

import (
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
