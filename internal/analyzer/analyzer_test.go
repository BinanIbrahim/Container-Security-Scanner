package analyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel-scanner/internal/extractor"
)

// file is one entry inside a synthetic layer tarball.
type file struct {
	name string
	body string
}

// layer is a synthetic image layer: a tar of files, optionally gzip-compressed,
// stored in the outer archive under blobName.
type layer struct {
	blobName string
	gzip     bool
	files    []file
}

// layerTar builds a single layer's tarball, gzipped when requested.
func layerTar(t *testing.T, l layer) []byte {
	t.Helper()

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, f := range l.files {
		hdr := &tar.Header{Name: f.name, Typeflag: tar.TypeReg, Size: int64(len(f.body)), Mode: 0o644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write layer header %q: %v", f.name, err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatalf("write layer body %q: %v", f.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer tar: %v", err)
	}

	if !l.gzip {
		return raw.Bytes()
	}

	var gzbuf bytes.Buffer
	gw := gzip.NewWriter(&gzbuf)
	if _, err := gw.Write(raw.Bytes()); err != nil {
		t.Fatalf("gzip layer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return gzbuf.Bytes()
}

// imageTar builds a saved-image tarball (the outer, uncompressed archive) on
// disk from the given layers and manifest layer order, and returns its path.
// manifestFirst controls whether manifest.json precedes or follows the layer
// blobs in the outer archive, exercising both orderings.
func imageTar(t *testing.T, layers []layer, manifestOrder []string, manifestFirst bool) string {
	t.Helper()

	manifest := Manifest{{Config: "config.json", Layers: manifestOrder}}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	writeEntry := func(name string, body []byte) {
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write outer header %q: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write outer body %q: %v", name, err)
		}
	}

	if manifestFirst {
		writeEntry(manifestName, manifestJSON)
	}
	for _, l := range layers {
		writeEntry(l.blobName, layerTar(t, l))
	}
	if !manifestFirst {
		writeEntry(manifestName, manifestJSON)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close outer tar: %v", err)
	}

	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write image tar: %v", err)
	}
	return path
}

const apkDB = "C:Q1\nP:musl\nV:1.2.4-r0\n\nC:Q2\nP:busybox\nV:1.36.1-r0\n"

func TestBuildSBOM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		layers        []layer
		manifestOrder []string
		manifestFirst bool
		want          []Package
		wantErr       string
	}{
		{
			name: "single plain layer with apk db",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: apkDB}}},
			},
			manifestOrder: []string{"l1"},
			manifestFirst: true,
			want: []Package{
				{Name: "musl", Version: "1.2.4-r0"},
				{Name: "busybox", Version: "1.36.1-r0"},
			},
		},
		{
			name: "gzip-compressed layer",
			layers: []layer{
				{blobName: "l1", gzip: true, files: []file{{name: apkDBPath, body: apkDB}}},
			},
			manifestOrder: []string{"l1"},
			manifestFirst: true,
			want: []Package{
				{Name: "musl", Version: "1.2.4-r0"},
				{Name: "busybox", Version: "1.36.1-r0"},
			},
		},
		{
			name: "manifest after layers in outer tar",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: apkDB}}},
			},
			manifestOrder: []string{"l1"},
			manifestFirst: false,
			want: []Package{
				{Name: "musl", Version: "1.2.4-r0"},
				{Name: "busybox", Version: "1.36.1-r0"},
			},
		},
		{
			name: "later layer rewrites db wins in manifest order",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: "P:musl\nV:1.0.0-r0\n"}}},
				{blobName: "l2", files: []file{{name: apkDBPath, body: "P:musl\nV:9.9.9-r0\n"}}},
			},
			manifestOrder: []string{"l1", "l2"},
			manifestFirst: true,
			want:          []Package{{Name: "musl", Version: "9.9.9-r0"}},
		},
		{
			name: "winner follows manifest order not tar order",
			// l2 (the manifest's last layer) carries the winning db, but it is
			// written to the outer archive BEFORE l1 — proving resolution uses
			// manifest order, not the order blobs appear in the tar.
			layers: []layer{
				{blobName: "l2", files: []file{{name: apkDBPath, body: "P:musl\nV:9.9.9-r0\n"}}},
				{blobName: "l1", files: []file{{name: apkDBPath, body: "P:musl\nV:1.0.0-r0\n"}}},
			},
			manifestOrder: []string{"l1", "l2"},
			manifestFirst: true,
			want:          []Package{{Name: "musl", Version: "9.9.9-r0"}},
		},
		{
			name: "whiteout in later layer deletes db",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: apkDB}}},
				{blobName: "l2", files: []file{{name: apkDBWhiteout, body: ""}}},
			},
			manifestOrder: []string{"l1", "l2"},
			manifestFirst: true,
			wantErr:       "could not find",
		},
		{
			name: "opaque whiteout in later layer deletes db",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: apkDB}}},
				{blobName: "l2", files: []file{{name: apkDBOpaque, body: ""}}},
			},
			manifestOrder: []string{"l1", "l2"},
			manifestFirst: true,
			wantErr:       "could not find",
		},
		{
			name: "db readded after whiteout",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: "P:musl\nV:1.0.0-r0\n"}}},
				{blobName: "l2", files: []file{{name: apkDBWhiteout, body: ""}}},
				{blobName: "l3", files: []file{{name: apkDBPath, body: "P:musl\nV:2.0.0-r0\n"}}},
			},
			manifestOrder: []string{"l1", "l2", "l3"},
			manifestFirst: true,
			want:          []Package{{Name: "musl", Version: "2.0.0-r0"}},
		},
		{
			name: "no apk db anywhere",
			layers: []layer{
				{blobName: "l1", files: []file{{name: "etc/hostname", body: "host"}}},
			},
			manifestOrder: []string{"l1"},
			manifestFirst: true,
			wantErr:       "could not find",
		},
		{
			name: "empty apk db yields not-found, not empty sbom",
			layers: []layer{
				{blobName: "l1", files: []file{{name: apkDBPath, body: ""}}},
			},
			manifestOrder: []string{"l1"},
			manifestFirst: true,
			wantErr:       "could not find",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := imageTar(t, tc.layers, tc.manifestOrder, tc.manifestFirst)
			got, err := BuildSBOM(path, extractor.New(), Options{})

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("BuildSBOM succeeded, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("BuildSBOM error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("BuildSBOM returned error: %v", err)
			}
			if !equalPackages(got, tc.want) {
				t.Fatalf("BuildSBOM packages = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBuildSBOM_OversizedEntryTrippedCap confirms the streaming path still
// enforces the per-entry size cap inherited from the extractor: an apk database
// larger than the cap fails rather than being buffered whole.
func TestBuildSBOM_OversizedEntryTrippedCap(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("P:x\nV:1\n", 200)
	path := imageTar(t,
		[]layer{{blobName: "l1", files: []file{{name: apkDBPath, body: big}}}},
		[]string{"l1"}, true)

	ext := &extractor.Extractor{FileSizeCap: 16, TotalSizeCap: extractor.DefaultTotalSizeCap}
	if _, err := BuildSBOM(path, ext, Options{}); err == nil {
		t.Fatal("BuildSBOM succeeded, want per-entry cap error")
	}
}

func TestGetImageLayers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr string
	}{
		{
			name:  "valid manifest",
			input: `[{"Config":"c.json","RepoTags":["alpine:3.19"],"Layers":["a","b"]}]`,
			want:  []string{"a", "b"},
		},
		{
			name:    "empty manifest array",
			input:   `[]`,
			wantErr: "no layers found",
		},
		{
			name:    "no layers",
			input:   `[{"Config":"c.json","Layers":[]}]`,
			wantErr: "no layers found",
		},
		{
			name:    "malformed json",
			input:   `{not json`,
			wantErr: "parse manifest.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetImageLayers(strings.NewReader(tc.input))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("GetImageLayers error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetImageLayers returned error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("GetImageLayers = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseAlpineDB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []Package
	}{
		{
			name:  "two packages",
			input: "P:musl\nV:1.2.4-r0\n\nP:busybox\nV:1.36.1-r0\n",
			want: []Package{
				{Name: "musl", Version: "1.2.4-r0"},
				{Name: "busybox", Version: "1.36.1-r0"},
			},
		},
		{
			name:  "version without name is skipped until paired",
			input: "P:zlib\nV:1.3-r0\n",
			want:  []Package{{Name: "zlib", Version: "1.3-r0"}},
		},
		{
			name:  "name without version produces nothing",
			input: "P:orphan\n",
			want:  nil,
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseAlpineDB(strings.NewReader(tc.input))
			if !equalPackages(got, tc.want) {
				t.Fatalf("parseAlpineDB = %v, want %v", got, tc.want)
			}
		})
	}
}

func equalPackages(a, b []Package) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
