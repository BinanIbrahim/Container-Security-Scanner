// internal/extractor/extractor.go
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
		os.RemoveAll(tempDir)
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
	if err := os.Mkdir(extractPath, 0755); err != nil {
		return "", cleanup, fmt.Errorf("failed to create extract dir: %w", err)
	}

	if verbose {
		fmt.Println("Unpacking image layers...")
	}
	if err := untar(tarPath, extractPath); err != nil {
		return "", cleanup, fmt.Errorf("failed to untar image: %w", err)
	}

	return extractPath, cleanup, nil
}

// untar is a helper function to extract a tarball to a target directory
func untar(tarball, targetDir string) error {
	reader, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer reader.Close()

	tr := tar.NewReader(reader)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}

		// SECURITY BONUS: Prevent "Zip-Slip" vulnerability (Path Traversal)
		targetPath := filepath.Join(targetDir, header.Name)
		if !strings.HasPrefix(targetPath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			// Ensure parent directories exist
			os.MkdirAll(filepath.Dir(targetPath), 0755)
			outFile, err := os.Create(targetPath)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
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
