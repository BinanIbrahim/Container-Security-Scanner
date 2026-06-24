// Package extractor saves a Docker image via the docker CLI and unpacks its
// layers into a temporary directory for analysis.
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

// ExtractImage saves the docker image to a temporary directory and unpacks it.
// It returns the path to the unpacked directory, and a cleanup function.
func ExtractImage(imageName string, verbose bool) (string, func(), error) {
	// 1. Create a secure temporary directory
	tempDir, err := os.MkdirTemp("", "sentinel-scanner-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Setup our cleanup function to wipe the temp files when we are done
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		if verbose {
			fmt.Println("Cleaned up temporary files.")
		}
	}

	tarPath := filepath.Join(tempDir, "image.tar")
	extractPath := filepath.Join(tempDir, "unpacked")

	// 2. Shell out to Docker to save the image
	if verbose {
		fmt.Printf("Pulling and saving image '%s' (this might take a moment)...\n", imageName)
	}

	// Find the docker binary safely
	dockerBinary := getDockerPath()

	// 1.5. Pull the image from the registry to ensure it exists locally
	if verbose {
		fmt.Printf("Pulling image '%s' from registry...\n", imageName)
	}
	pullCmd := exec.Command(dockerBinary, "pull", imageName)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		return "", cleanup, fmt.Errorf("docker pull failed: %v\nOutput: %s", err, output)
	}

	// 2. Shell out to Docker to save the image
	if verbose {
		fmt.Printf("Pulling and saving image '%s' (using binary: %s)...\n", imageName, dockerBinary)
	}
	cmd := exec.Command(dockerBinary, "save", "-o", tarPath, imageName)

	// Capture standard error in case docker fails (e.g., daemon not running)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", cleanup, fmt.Errorf("docker save failed: %v\nOutput: %s", err, output)
	}

	// 3. Unpack the tarball
	if err := os.Mkdir(extractPath, 0750); err != nil {
		return "", cleanup, fmt.Errorf("failed to create extract dir: %w", err)
	}

	if verbose {
		fmt.Println("Unpacking image layers...")
	}
	if err := New().Untar(tarPath, extractPath); err != nil {
		return "", cleanup, fmt.Errorf("failed to untar image: %w", err)
	}

	return extractPath, cleanup, nil
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
