// Package analyzer streams the layers of a saved Docker image tarball to locate
// and parse the Alpine package database, producing the software bill of
// materials (SBOM) without unpacking the image to disk.
package analyzer

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"sentinel-scanner/internal/extractor"
)

// Manifest represents the structure of the Docker manifest.json file.
type Manifest []struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// GetImageLayers decodes a Docker manifest.json and returns the ordered list of
// layer tarball paths.
func GetImageLayers(manifest io.Reader) ([]string, error) {
	var m Manifest
	if err := json.NewDecoder(manifest).Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}

	if len(m) == 0 || len(m[0].Layers) == 0 {
		return nil, fmt.Errorf("invalid manifest: no layers found")
	}

	return m[0].Layers, nil
}

// Package represents a single installed software package.
type Package struct {
	Name    string
	Version string
}

// Options configures SBOM construction.
type Options struct {
	// Verbose enables progress output to stdout.
	Verbose bool
}

const (
	manifestName  = "manifest.json"
	apkDBPath     = "lib/apk/db/installed"
	apkDBWhiteout = "lib/apk/db/.wh.installed"
	apkDBOpaque   = "lib/apk/db/.wh..wh..opq"
)

// layerResult records what a single layer did to the apk database: it either
// wrote a new copy (db != nil) or deleted it via an OCI whiteout.
type layerResult struct {
	db       []byte
	whiteout bool
}

// BuildSBOM streams the layers of the saved Docker image at imageTarPath, finds
// the Alpine package database as it exists in the final merged filesystem,
// parses it, and returns the installed packages (the SBOM). Layers are never
// written to disk; ext supplies the size caps that bound the work against tar
// bombs, shared cumulatively across every layer.
func BuildSBOM(imageTarPath string, ext *extractor.Extractor, opts Options) ([]Package, error) {
	walker := ext.NewStreamWalker()

	// Pass 1: locate and decode manifest.json. Its position in the outer archive
	// is not guaranteed (Docker emits layer blobs before it), so we read the
	// whole archive to find it.
	layers, err := readLayers(imageTarPath, walker)
	if err != nil {
		return nil, err
	}
	layerSet := make(map[string]bool, len(layers))
	for _, l := range layers {
		layerSet[l] = true
	}

	// Pass 2: scan each layer blob for the apk database, keyed by layer name.
	// We cannot resolve "last write wins" during the walk because the outer tar
	// is not ordered by the manifest, so we record per-layer results and resolve
	// afterwards.
	results := make(map[string]layerResult, len(layers))
	scan := func(hdr *tar.Header, body io.Reader) error {
		if !layerSet[hdr.Name] {
			return nil // config blob or other non-layer entry
		}
		res, err := scanLayer(walker, body)
		if err != nil {
			return fmt.Errorf("scan layer %q: %w", hdr.Name, err)
		}
		if res.db != nil || res.whiteout {
			results[hdr.Name] = res
			if opts.Verbose && res.db != nil {
				fmt.Println("Found Alpine package database in layer:", hdr.Name)
			}
		}
		return nil
	}
	if err := walkArchive(imageTarPath, walker, scan); err != nil {
		return nil, err
	}

	// Resolve in manifest order: the last layer to write the database wins, and
	// a whiteout deletes any database carried from earlier layers.
	var winning []byte
	for _, l := range layers {
		res, ok := results[l]
		if !ok {
			continue
		}
		if res.whiteout {
			winning = nil
			continue
		}
		winning = res.db
	}

	// A whiteout (winning == nil) or an empty/unparseable database both yield
	// zero packages; report that as "not found" rather than an empty SBOM, the
	// same contract the disk-based path enforced.
	sbom := parseAlpineDB(bytes.NewReader(winning))
	if len(sbom) == 0 {
		return nil, fmt.Errorf("could not find %s in any layer (is this an Alpine image?)", apkDBPath)
	}

	return sbom, nil
}

// walkArchive opens the saved image tarball and walks its outer (uncompressed)
// tar stream with fn under the walker's shared size budget.
func walkArchive(imageTarPath string, walker *extractor.StreamWalker, fn extractor.WalkFunc) error {
	file, err := os.Open(imageTarPath)
	if err != nil {
		return fmt.Errorf("open image tarball: %w", err)
	}
	defer func() { _ = file.Close() }()

	return walker.Walk(file, fn)
}

// readLayers walks the outer archive to find manifest.json and returns its
// ordered layer list.
func readLayers(imageTarPath string, walker *extractor.StreamWalker) ([]string, error) {
	var layers []string
	var found bool

	err := walkArchive(imageTarPath, walker, func(hdr *tar.Header, body io.Reader) error {
		if hdr.Name != manifestName {
			return nil
		}
		l, err := GetImageLayers(body)
		if err != nil {
			return err
		}
		layers, found = l, true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("could not find manifest.json in image tarball")
	}

	return layers, nil
}

// scanLayer descends into a single layer blob — gzip-compressed or plain tar —
// and reports whether it writes or deletes the apk database. The descent reuses
// walker so inner entries draw against the same cumulative size budget.
func scanLayer(walker *extractor.StreamWalker, body io.Reader) (layerResult, error) {
	// Peek at the first 2 bytes to detect the gzip magic signature without
	// consuming the stream.
	br := bufio.NewReader(body)
	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return layerResult{}, err
	}

	var src io.Reader = br
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzr, err := gzip.NewReader(br)
		if err != nil {
			return layerResult{}, fmt.Errorf("gzip reader: %w", err)
		}
		defer func() { _ = gzr.Close() }()
		src = gzr
	}

	var res layerResult
	err = walker.Walk(src, func(hdr *tar.Header, entry io.Reader) error {
		switch hdr.Name {
		case apkDBPath:
			b, err := io.ReadAll(entry)
			if err != nil {
				return fmt.Errorf("read apk database: %w", err)
			}
			res.db = b
			res.whiteout = false
		case apkDBWhiteout, apkDBOpaque:
			res.db = nil
			res.whiteout = true
		}
		return nil
	})
	if err != nil {
		return layerResult{}, err
	}

	return res, nil
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
