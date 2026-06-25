package extractor

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
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

// member is a synthetic tar entry carrying a body, used to build archives
// in-memory for streaming tests.
type member struct {
	name     string
	typeflag byte
	body     []byte
}

// tarBytes builds a tarball in memory and returns its bytes.
func tarBytes(t *testing.T, members []member) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		flag := m.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		hdr := &tar.Header{Name: m.name, Typeflag: flag, Size: int64(len(m.body)), Mode: 0o644}
		if flag == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", m.name, err)
		}
		if len(m.body) > 0 {
			if _, err := tw.Write(m.body); err != nil {
				t.Fatalf("write body %q: %v", m.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}

func TestWalkStream_DeliversRegularFiles(t *testing.T) {
	t.Parallel()

	archive := tarBytes(t, []member{
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "dir/a.txt", body: []byte("alpha")},
		{name: "link", typeflag: tar.TypeSymlink},
		{name: "b.txt", body: []byte("bravo")},
		// A legitimate OCI opaque whiteout marker: its name embeds ".." but has
		// no ".." path component, so it must be delivered, not rejected.
		{name: "lib/apk/db/.wh..wh..opq"},
	})

	got := make(map[string]string)
	w := New().NewStreamWalker()
	err := w.Walk(bytes.NewReader(archive), func(hdr *tar.Header, body io.Reader) error {
		b, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		got[hdr.Name] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	want := map[string]string{
		"dir/a.txt":               "alpha",
		"b.txt":                   "bravo",
		"lib/apk/db/.wh..wh..opq": "",
	}
	if len(got) != len(want) {
		t.Fatalf("delivered %d regular entries, want %d (%v)", len(got), len(want), got)
	}
	for name, body := range want {
		if got[name] != body {
			t.Errorf("entry %q body = %q, want %q", name, got[name], body)
		}
	}
}

func TestWalkStream_RejectedEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		members  []member
		fileCap  int64
		totalCap int64
		readBody bool // whether the callback consumes each body (for total cap)
		wantErr  string
	}{
		{
			name:    "path traversal via ..",
			members: []member{{name: "../evil.txt", body: []byte("x")}},
			wantErr: "path traversal",
		},
		{
			name:    "absolute path",
			members: []member{{name: "/etc/passwd", body: []byte("x")}},
			wantErr: "path traversal",
		},
		{
			name:    "nested dotdot component",
			members: []member{{name: "a/../../b", body: []byte("x")}},
			wantErr: "path traversal",
		},
		{
			name:    "single entry over file cap",
			members: []member{{name: "big.txt", body: make([]byte, 1025)}},
			fileCap: 1024,
			wantErr: "file size exceeds cap",
		},
		{
			name: "cumulative over total cap",
			members: []member{
				{name: "a.txt", body: make([]byte, 1024)},
				{name: "b.txt", body: make([]byte, 1024)},
			},
			fileCap:  1024,
			totalCap: 1024,
			readBody: true,
			wantErr:  "total extraction size exceeds cap",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			archive := tarBytes(t, tc.members)
			e := &Extractor{FileSizeCap: tc.fileCap, TotalSizeCap: tc.totalCap}
			err := e.NewStreamWalker().Walk(bytes.NewReader(archive), func(_ *tar.Header, body io.Reader) error {
				if tc.readBody {
					_, err := io.Copy(io.Discard, body)
					return err
				}
				return nil
			})
			if err == nil {
				t.Fatalf("Walk succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Walk error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestWalkStream_TotalCapSpansNestedWalks locks in the whole-image cumulative
// budget: bytes read while descending into one stream and then a second, via
// the same StreamWalker, accumulate against a single total cap.
func TestWalkStream_TotalCapSpansNestedWalks(t *testing.T) {
	t.Parallel()

	inner := tarBytes(t, []member{{name: "file", body: make([]byte, 1024)}})
	outer := tarBytes(t, []member{
		{name: "layer-a", body: inner},
		{name: "layer-b", body: inner},
	})

	// Per-entry cap is generous; the total cap is only large enough for one
	// inner file's worth of bytes, so reading both layers must trip it.
	e := &Extractor{FileSizeCap: 1 << 20, TotalSizeCap: 1500}
	w := e.NewStreamWalker()
	err := w.Walk(bytes.NewReader(outer), func(_ *tar.Header, body io.Reader) error {
		// Descend into the layer with the SAME walker so the budget is shared.
		return w.Walk(body, func(_ *tar.Header, entry io.Reader) error {
			_, err := io.Copy(io.Discard, entry)
			return err
		})
	})
	if err == nil {
		t.Fatal("Walk succeeded, want cumulative total cap error across nested walks")
	}
	if !strings.Contains(err.Error(), "total extraction size exceeds cap") {
		t.Fatalf("Walk error = %q, want total cap error", err.Error())
	}
}

// TestWalkStream_PropagatesCallbackError confirms a callback error stops the
// walk and surfaces unchanged.
func TestWalkStream_PropagatesCallbackError(t *testing.T) {
	t.Parallel()

	archive := tarBytes(t, []member{{name: "a.txt", body: []byte("x")}})
	sentinel := fmt.Errorf("boom")
	err := New().NewStreamWalker().Walk(bytes.NewReader(archive), func(_ *tar.Header, _ io.Reader) error {
		return sentinel
	})
	if err != sentinel {
		t.Fatalf("Walk error = %v, want %v", err, sentinel)
	}
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
