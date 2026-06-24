package extractor

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// entry is a synthetic tar member used to build archives in-memory.
type entry struct {
	name     string
	typeflag byte
	linkname string
	size     int64 // for TypeReg; body is `size` zero bytes
}

// writeTar builds a tarball on disk under dir and returns its path.
func writeTar(t *testing.T, dir string, entries []entry) string {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Linkname: e.linkname,
			Size:     e.size,
			Mode:     0o644,
		}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg && e.size > 0 {
			if _, err := tw.Write(make([]byte, e.size)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	path := filepath.Join(dir, "test.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tar file: %v", err)
	}
	return path
}

func TestUntar_SafeEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []entry
	}{
		{
			name:    "regular file in root",
			entries: []entry{{name: "file.txt", typeflag: tar.TypeReg, size: 10}},
		},
		{
			name: "regular file in subdir",
			entries: []entry{
				{name: "sub/", typeflag: tar.TypeDir},
				{name: "sub/file.txt", typeflag: tar.TypeReg, size: 5},
			},
		},
		{
			name:    "directory entry",
			entries: []entry{{name: "sub/", typeflag: tar.TypeDir}},
		},
		{
			name: "symlink within root",
			entries: []entry{
				{name: "target.txt", typeflag: tar.TypeReg, size: 3},
				{name: "link.txt", typeflag: tar.TypeSymlink, linkname: "target.txt"},
			},
		},
		{
			name: "hardlink within root",
			entries: []entry{
				{name: "target.txt", typeflag: tar.TypeReg, size: 3},
				{name: "hard.txt", typeflag: tar.TypeLink, linkname: "target.txt"},
			},
		},
		{
			name:    "file exactly at size cap",
			entries: []entry{{name: "big.txt", typeflag: tar.TypeReg, size: 1024}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tarPath := writeTar(t, dir, tc.entries)
			target := filepath.Join(dir, "out")
			if err := os.Mkdir(target, 0o750); err != nil {
				t.Fatalf("mkdir target: %v", err)
			}

			e := &Extractor{FileSizeCap: 1024, TotalSizeCap: DefaultTotalSizeCap}
			if err := e.Untar(tarPath, target); err != nil {
				t.Fatalf("Untar returned error: %v", err)
			}
		})
	}
}

func TestUntar_RejectedEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []entry
		fileCap int64
		totCap  int64
		wantErr string
	}{
		{
			name:    "path traversal via ..",
			entries: []entry{{name: "../evil.txt", typeflag: tar.TypeReg, size: 1}},
			wantErr: "path traversal",
		},
		{
			name:    "absolute path",
			entries: []entry{{name: "/etc/passwd", typeflag: tar.TypeReg, size: 1}},
			wantErr: "path traversal",
		},
		{
			name:    "file one byte over cap",
			entries: []entry{{name: "big.txt", typeflag: tar.TypeReg, size: 1025}},
			fileCap: 1024,
			wantErr: "file size exceeds cap",
		},
		{
			name: "total size exceeded",
			entries: []entry{
				{name: "a.txt", typeflag: tar.TypeReg, size: 1024},
				{name: "b.txt", typeflag: tar.TypeReg, size: 1024},
			},
			fileCap: 1024,
			totCap:  1024,
			wantErr: "total extraction size exceeds cap",
		},
		{
			name:    "symlink escapes root relative",
			entries: []entry{{name: "link.txt", typeflag: tar.TypeSymlink, linkname: "../../etc/passwd"}},
			wantErr: "escapes extraction root",
		},
		{
			name:    "symlink escapes root absolute",
			entries: []entry{{name: "link.txt", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
			wantErr: "escapes extraction root",
		},
		{
			name:    "hardlink escapes root",
			entries: []entry{{name: "hard.txt", typeflag: tar.TypeLink, linkname: "../../etc/passwd"}},
			wantErr: "escapes extraction root",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tarPath := writeTar(t, dir, tc.entries)
			target := filepath.Join(dir, "out")
			if err := os.Mkdir(target, 0o750); err != nil {
				t.Fatalf("mkdir target: %v", err)
			}

			e := &Extractor{FileSizeCap: tc.fileCap, TotalSizeCap: tc.totCap}
			err := e.Untar(tarPath, target)
			if err == nil {
				t.Fatalf("Untar succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Untar error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestUntar_RejectsChainedSymlinkEscape locks in the property that the
// lexical-only link check is sound against multi-hop symlink chains: an
// in-tree symlink cannot be combined with a second symlink to write through
// to a path outside the extraction root.
func TestUntar_RejectsChainedSymlinkEscape(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "out")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	// A file that lives outside the extraction root and must stay untouched.
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("original"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// good/ is in-tree; a -> good is a benign symlink; a/b -> ../../outside
	// escapes and must be rejected, so the write-through file never lands.
	tarPath := writeTar(t, dir, []entry{
		{name: "good/", typeflag: tar.TypeDir},
		{name: "a", typeflag: tar.TypeSymlink, linkname: "good"},
		{name: "a/b", typeflag: tar.TypeSymlink, linkname: "../../outside"},
		{name: "a/b/secret", typeflag: tar.TypeReg, size: 5},
	})

	if err := New().Untar(tarPath, target); err == nil {
		t.Fatal("Untar succeeded, want error rejecting chained symlink escape")
	}

	got, err := os.ReadFile(secret)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("secret was modified to %q, want %q", got, "original")
	}
}

func TestIsSafePath(t *testing.T) {
	t.Parallel()

	root := filepath.Clean("/tmp/x")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "simple name", path: "foo", want: true},
		{name: "nested name", path: "a/b/c", want: true},
		{name: "parent escape", path: "../sibling", want: false},
		{name: "nested parent escape", path: "a/../../b", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isSafePath(root, tc.path); got != tc.want {
				t.Fatalf("isSafePath(%q, %q) = %v, want %v", root, tc.path, got, tc.want)
			}
		})
	}
}

func TestExtractorDefaultCaps(t *testing.T) {
	t.Parallel()

	e := New()
	if got := e.fileSizeCap(); got != DefaultFileSizeCap {
		t.Errorf("fileSizeCap() = %d, want %d", got, DefaultFileSizeCap)
	}
	if got := e.totalSizeCap(); got != DefaultTotalSizeCap {
		t.Errorf("totalSizeCap() = %d, want %d", got, DefaultTotalSizeCap)
	}

	// Zero-value Extractor must also fall back to the defaults.
	var zero Extractor
	if got := zero.fileSizeCap(); got != DefaultFileSizeCap {
		t.Errorf("zero fileSizeCap() = %d, want %d", got, DefaultFileSizeCap)
	}
	if got := zero.totalSizeCap(); got != DefaultTotalSizeCap {
		t.Errorf("zero totalSizeCap() = %d, want %d", got, DefaultTotalSizeCap)
	}
}

func TestExtractorCustomCaps(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "out")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	// A file exactly at the cap must succeed.
	atCap := writeTar(t, dir, []entry{{name: "at.txt", typeflag: tar.TypeReg, size: 100}})
	e := &Extractor{FileSizeCap: 100}
	if err := e.Untar(atCap, target); err != nil {
		t.Fatalf("file at cap: unexpected error: %v", err)
	}

	// One byte over the cap must fail.
	over := writeTar(t, dir, []entry{{name: "over.txt", typeflag: tar.TypeReg, size: 101}})
	if err := e.Untar(over, target); err == nil {
		t.Fatal("file over cap: expected error, got nil")
	}
}
