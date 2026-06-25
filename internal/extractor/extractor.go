// Package extractor saves a Docker image via the docker CLI and provides
// primitives for reading its layers — either unpacking them to disk or walking
// them in memory — under tar-bomb size guards.
package extractor

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Options configures image extraction.
type Options struct {
	// Verbose enables progress output to stdout.
	Verbose bool
}

// SaveImage pulls imageName and writes it to a tarball via `docker save`,
// returning the path to that tarball and a cleanup function that removes the
// temporary directory holding it. The image is not unpacked; callers stream its
// layers directly from the saved tar (see Extractor.NewStreamWalker).
func SaveImage(imageName string, opts Options) (string, func(), error) {
	// 1. Create a secure temporary directory
	tempDir, err := os.MkdirTemp("", "sentinel-scanner-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	// Setup our cleanup function to wipe the temp files when we are done
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		if opts.Verbose {
			fmt.Println("Cleaned up temporary files.")
		}
	}

	tarPath := filepath.Join(tempDir, "image.tar")

	// Find the docker binary safely
	dockerBinary := getDockerPath()

	// Pull the image from the registry to ensure it exists locally
	if opts.Verbose {
		fmt.Printf("Pulling image '%s' from registry...\n", imageName)
	}
	pullCmd := exec.Command(dockerBinary, "pull", imageName)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		return "", cleanup, fmt.Errorf("docker pull failed: %v\nOutput: %s", err, output)
	}

	// Shell out to Docker to save the image
	if opts.Verbose {
		fmt.Printf("Saving image '%s' (using binary: %s)...\n", imageName, dockerBinary)
	}
	cmd := exec.Command(dockerBinary, "save", "-o", tarPath, imageName)

	// Capture standard error in case docker fails (e.g., daemon not running)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", cleanup, fmt.Errorf("docker save failed: %v\nOutput: %s", err, output)
	}

	return tarPath, cleanup, nil
}

// DefaultFileSizeCap is the maximum number of bytes extracted for a single tar
// entry. Entries exceeding this limit cause extraction to fail, guarding
// against tar bombs that inflate one file to fill the disk.
const DefaultFileSizeCap int64 = 512 << 20 // 512 MiB

// DefaultTotalSizeCap is the maximum number of bytes extracted across all
// entries in a single call to Untar. A layer that pushes the cumulative total
// past this limit causes extraction to fail.
const DefaultTotalSizeCap int64 = 2 << 30 // 2 GiB

// Extractor holds configuration for unpacking container image tarballs safely.
type Extractor struct {
	// FileSizeCap is the per-entry byte limit. Zero means DefaultFileSizeCap.
	FileSizeCap int64
	// TotalSizeCap is the cumulative byte limit across all entries in a single
	// Untar call. Zero means DefaultTotalSizeCap.
	TotalSizeCap int64
}

// New returns an Extractor configured with the default size caps.
func New() *Extractor {
	return &Extractor{
		FileSizeCap:  DefaultFileSizeCap,
		TotalSizeCap: DefaultTotalSizeCap,
	}
}

// fileSizeCap returns the effective per-entry cap, substituting the default
// when the field is left at its zero value.
func (e *Extractor) fileSizeCap() int64 {
	if e.FileSizeCap <= 0 {
		return DefaultFileSizeCap
	}
	return e.FileSizeCap
}

// totalSizeCap returns the effective cumulative cap, substituting the default
// when the field is left at its zero value.
func (e *Extractor) totalSizeCap() int64 {
	if e.TotalSizeCap <= 0 {
		return DefaultTotalSizeCap
	}
	return e.TotalSizeCap
}

// Untar extracts a tarball into targetDir, enforcing the configured size caps
// and rejecting any entry whose path — or symlink/hardlink target — escapes
// the extraction root.
func (e *Extractor) Untar(tarball, targetDir string) error {
	reader, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	tr := tar.NewReader(reader)

	var totalBytes int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}

		// Defence in depth: reject absolute paths and any ".." component before
		// we touch the filesystem. The check is intentionally coarse — it would
		// also reject an unusual-but-legal name like "foo..bar" — because for a
		// security scanner a false rejection is cheaper than a missed traversal.
		if filepath.IsAbs(header.Name) || strings.Contains(header.Name, "..") {
			return fmt.Errorf("extract entry %q: path traversal detected", header.Name)
		}

		// SECURITY: Prevent "Zip-Slip" (path traversal). The gosec G305 finding
		// on the Join is mitigated by isSafePath immediately below.
		targetPath := filepath.Join(targetDir, header.Name) //nolint:gosec // G305 guarded by isSafePath below
		if !isSafePath(targetDir, header.Name) {
			return fmt.Errorf("extract entry %q: path traversal detected", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0750); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
		case tar.TypeReg:
			// Ensure parent directories exist
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
			// Cap the copy at fileSizeCap+1 so we can tell "fit exactly" from
			// "overflowed" without a second read of the underlying stream.
			limit := e.fileSizeCap()
			n, err := io.Copy(outFile, io.LimitReader(tr, limit+1))
			if err != nil {
				_ = outFile.Close()
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
			if n > limit {
				return fmt.Errorf("extract entry %q: file size exceeds cap of %d bytes", header.Name, limit)
			}
			totalBytes += n
			if totalBytes > e.totalSizeCap() {
				return fmt.Errorf("extract entry %q: total extraction size exceeds cap of %d bytes", header.Name, e.totalSizeCap())
			}
		case tar.TypeSymlink:
			// Resolve the link target relative to the entry's own directory and
			// confirm it stays in-tree. An absolute Linkname must be checked as
			// an absolute path — filepath.Join would silently re-root it.
			// NOTE: this does not chase symlink chains; callers that resolve
			// links after extraction must re-check with filepath.EvalSymlinks.
			linkDir := filepath.Dir(targetPath)
			if linkEscapes(linkDir, targetDir, header.Linkname) {
				return fmt.Errorf("extract entry %q: symlink target %q escapes extraction root", header.Name, header.Linkname)
			}
			if err := os.MkdirAll(linkDir, 0750); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
		case tar.TypeLink:
			// Hardlink targets are conventionally relative to the extraction
			// root. Resolve against it (treating an absolute target literally)
			// and reject anything that escapes.
			if linkEscapes(targetDir, targetDir, header.Linkname) {
				return fmt.Errorf("extract entry %q: hardlink target %q escapes extraction root", header.Name, header.Linkname)
			}
			linkTarget := filepath.Join(targetDir, header.Linkname) //nolint:gosec // G305 guarded by linkEscapes above
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
			if err := os.Link(linkTarget, targetPath); err != nil {
				return fmt.Errorf("extract entry %q: %w", header.Name, err)
			}
		}
	}
	return nil
}

// WalkFunc is invoked for each regular-file entry encountered by
// StreamWalker.Walk. body is capped at the per-entry size limit; reading past it
// causes the walk to fail. Returning a non-nil error stops the walk and is
// propagated to the caller. body must not be retained after fn returns.
type WalkFunc func(hdr *tar.Header, body io.Reader) error

// StreamWalker walks one or more tar streams under a single shared cumulative
// size budget, enforcing the same per-entry and total caps as Untar without
// writing anything to disk. A walker is created per image so the cumulative cap
// spans every layer (and the bytes drawn descending into them), mirroring the
// whole-image budget the disk-based Untar enforced.
type StreamWalker struct {
	ext   *Extractor
	total int64
}

// NewStreamWalker returns a StreamWalker that draws against the extractor's
// configured caps. Reuse one walker across an image's layers so the total cap
// is cumulative; create a fresh walker per image.
func (e *Extractor) NewStreamWalker() *StreamWalker {
	return &StreamWalker{ext: e}
}

// Walk reads the tar stream r and calls fn for each regular-file entry. Entry
// names that are absolute or contain a ".." path component are rejected. Each
// body fn receives is bounded by the per-entry cap, and every byte fn reads —
// at this level or any nested Walk sharing this StreamWalker — draws down the
// shared total budget. Non-regular entries (directories, links) are skipped;
// because nothing is written to disk, their link targets need no resolution.
func (w *StreamWalker) Walk(r io.Reader, fn WalkFunc) error {
	tr := tar.NewReader(r)
	fileCap := w.ext.fileSizeCap()
	totalCap := w.ext.totalSizeCap()

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Reject path traversal up front. Unlike Untar's coarse substring check
		// (which writes to disk and so errs on the side of rejection), a stream
		// walk only matches entry names, so we reject a ".." path component
		// precisely — this lets through legitimate OCI whiteout markers such as
		// ".wh..wh..opq" whose names embed "..".
		if filepath.IsAbs(header.Name) || hasDotDotComponent(header.Name) {
			return fmt.Errorf("walk entry %q: path traversal detected", header.Name)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Reject any single entry whose declared size blows the per-entry cap
		// before we read or skip it.
		if header.Size > fileCap {
			return fmt.Errorf("walk entry %q: file size exceeds cap of %d bytes", header.Name, fileCap)
		}

		// Cap the body at fileCap+1 so a callback that reads it fully can tell
		// "fit exactly" from "overflowed", and count every consumed byte against
		// the shared cumulative budget.
		body := &countingReader{r: io.LimitReader(tr, fileCap+1), total: &w.total}
		if err := fn(header, body); err != nil {
			return err
		}
		if body.n > fileCap {
			return fmt.Errorf("walk entry %q: file size exceeds cap of %d bytes", header.Name, fileCap)
		}
		if w.total > totalCap {
			return fmt.Errorf("walk entry %q: total extraction size exceeds cap of %d bytes", header.Name, totalCap)
		}
	}
	return nil
}

// countingReader tracks how many bytes have been read both for the current
// entry (n) and across the whole walk (the shared total).
type countingReader struct {
	r     io.Reader
	n     int64
	total *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	*c.total += int64(n)
	return n, err
}

// hasDotDotComponent reports whether name contains a ".." path component,
// treating "/" as the separator regardless of host OS (tar paths are slash-based).
func hasDotDotComponent(name string) bool {
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// isSafePath reports whether joining root and name stays within root after
// cleaning, i.e. the entry does not escape the extraction directory.
func isSafePath(root, name string) bool {
	clean := filepath.Join(root, name)
	return strings.HasPrefix(clean, filepath.Clean(root)+string(os.PathSeparator))
}

// linkEscapes reports whether a link target points outside root. A relative
// target is resolved against base; an absolute target is checked literally,
// since that is exactly how the OS will resolve the link on disk.
func linkEscapes(base, root, linkname string) bool {
	var resolved string
	if filepath.IsAbs(linkname) {
		resolved = filepath.Clean(linkname)
	} else {
		resolved = filepath.Clean(filepath.Join(base, linkname))
	}
	return !strings.HasPrefix(resolved, filepath.Clean(root)+string(os.PathSeparator))
}

// getDockerPath attempts to find the Docker executable even if the environment PATH is messed up.
func getDockerPath() string {
	// First, try the standard system path
	if path, err := exec.LookPath("docker"); err == nil {
		return path
	}

	// If not found, check common absolute paths (especially for Apple Silicon Macs and standard Linux)
	commonPaths := []string{
		"/usr/local/bin/docker",            // Standard Mac/Linux
		"/opt/homebrew/bin/docker",         // Apple Silicon Mac (Homebrew)
		"/usr/bin/docker",                  // Standard Linux
		"/Users/Shared/.docker/bin/docker", // Older Docker Desktop for Mac
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p // Found it!
		}
	}

	// If all else fails, return the string "docker" and let the standard error trigger
	return "docker"
}
