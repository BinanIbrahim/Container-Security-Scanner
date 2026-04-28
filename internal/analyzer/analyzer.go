// internal/analyzer/analyzer.go
package analyzer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Manifest represents the structure of the Docker manifest.json file.
type Manifest []struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// GetImageLayers reads the manifest.json and returns the ordered list of layer tarballs.
func GetImageLayers(extractPath string) ([]string, error) {
	manifestPath := filepath.Join(extractPath, "manifest.json")

	file, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("could not open manifest.json: %w", err)
	}
	defer file.Close()

	var manifest Manifest
	if err := json.NewDecoder(file).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest.json: %w", err)
	}

	if len(manifest) == 0 || len(manifest[0].Layers) == 0 {
		return nil, fmt.Errorf("invalid manifest: no layers found")
	}

	return manifest[0].Layers, nil
}

// Package represents a single installed software package.
type Package struct {
	Name    string
	Version string
}

// BuildSBOM searches through the container layers to find the Alpine package database,
// parses it, and returns a list of installed packages (the SBOM).
func BuildSBOM(extractPath string, layers []string, verbose bool) ([]Package, error) {
	var sbom []Package

	// Iterate through the layers in the exact order specified by the manifest
	for _, layer := range layers {
		// Optimization: We wrap the file logic in an anonymous function (a closure).
		// This ensures 'defer file.Close()' runs immediately after each layer finishes processing,
		// preventing a file-descriptor memory leak on massive images with 100+ layers.
		err := func() error {
			layerPath := filepath.Join(extractPath, layer)

			file, err := os.Open(layerPath)
			if err != nil {
				return fmt.Errorf("failed to open layer %s: %w", layer, err)
			}
			defer file.Close() // Safely closes at the end of this anonymous function

			// We use bufio.Reader so we can "peek" ahead into the file stream without consuming it.
			br := bufio.NewReader(file)

			// Peek at the first 2 bytes to check for the GZIP magic signature
			headerBytes, err := br.Peek(2)
			if err != nil && err != io.EOF {
				return err
			}

			var tr *tar.Reader

			// GZIP magic numbers are 0x1f and 0x8b
			if len(headerBytes) == 2 && headerBytes[0] == 0x1f && headerBytes[1] == 0x8b {
				// Layer is COMPRESSED. Wrap our stream in a gzip decompressor.
				gzr, err := gzip.NewReader(br)
				if err != nil {
					return fmt.Errorf("failed to create gzip reader: %w", err)
				}
				defer gzr.Close()
				tr = tar.NewReader(gzr)
			} else {
				// Layer is UNCOMPRESSED plain tar.
				tr = tar.NewReader(br)
			}

			// Search inside the layer stream
			for {
				header, err := tr.Next()
				if err == io.EOF {
					break // End of this layer's tarball
				}
				if err != nil {
					return err
				}

				if header.Name == "lib/apk/db/installed" {
					if verbose {
						fmt.Println("Found Alpine package database in layer:", layer)
					}
					sbom = parseAlpineDB(tr)
				}
			}
			return nil
		}()

		if err != nil {
			return nil, err
		}
	}

	if len(sbom) == 0 {
		return nil, fmt.Errorf("could not find lib/apk/db/installed in any layer (is this an Alpine image?)")
	}

	return sbom, nil
}

// parseAlpineDB reads the custom text format of the Alpine installed database
func parseAlpineDB(reader io.Reader) []Package {
	var packages []Package
	scanner := bufio.NewScanner(reader)

	var currentPkg Package

	for scanner.Scan() {
		line := scanner.Text()

		// Alpine DB format uses prefixes. 'P:' is Package name, 'V:' is Version.
		if strings.HasPrefix(line, "P:") {
			currentPkg.Name = strings.TrimPrefix(line, "P:")
		} else if strings.HasPrefix(line, "V:") {
			currentPkg.Version = strings.TrimPrefix(line, "V:")
			// Once we have both Name and Version, add to our SBOM and reset
			packages = append(packages, currentPkg)
			currentPkg = Package{}
		}
	}

	return packages
}
