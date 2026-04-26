package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"sentinel-scanner/internal/analyzer"
	"sentinel-scanner/internal/extractor"
	"sentinel-scanner/internal/matcher"
)

func main() {
	imageFlag := flag.String("image", "", "Docker image to scan (e.g., alpine:latest)")
	flag.Parse()

	if *imageFlag == "" {
		fmt.Println("Usage: scanner --image <image-name>")
		os.Exit(1)
	}

	fmt.Printf("\n=== SENTINEL CONTAINER SCANNER ===\n")
	fmt.Printf("Target: %s\n\n", *imageFlag)

	// --- PHASE 1: EXTRACTION ---
	fmt.Println("[*] Phase 1: Extracting Image...")
	extractedPath, cleanup, err := extractor.ExtractImage(*imageFlag)
	if err != nil {
		log.Fatalf("Extraction failed: %v", err)
	}
	defer cleanup()

	// --- PHASE 2: ANALYSIS (SBOM) ---
	fmt.Println("[*] Phase 2: Analyzing Layers...")
	layers, err := analyzer.GetImageLayers(extractedPath)
	if err != nil {
		log.Fatalf("Failed to read manifest: %v", err)
	}

	sbom, err := analyzer.BuildSBOM(extractedPath, layers)
	if err != nil {
		log.Fatalf("Failed to build SBOM: %v", err)
	}
	fmt.Printf("    -> Generated SBOM with %d installed packages.\n", len(sbom))

	// --- PHASE 3: MATCHING (VULNERABILITIES) ---
	fmt.Println("[*] Phase 3: Vulnerability Matching...")

	// 1. Detect Alpine Version dynamically
	alpineVersion, err := detectAlpineVersion(*imageFlag, sbom)
	if err != nil {
		log.Fatalf("Failed to detect Alpine OS version from SBOM: %v", err)
	}
	fmt.Printf("    -> Detected Alpine OS Version: v%s\n", alpineVersion)

	// 2. Fetch the correct Security Database
	db, err := matcher.FetchSecDB(alpineVersion)
	if err != nil {
		log.Fatalf("Failed to fetch SecDB: %v", err)
	}
	fmt.Printf("    -> Loaded %d packages from Alpine SecDB.\n", len(db.Packages))

	// 3. Convert the SecDB slice into a Map for fast lookups
	vulnMap := make(map[string]matcher.SecPackage)
	for _, p := range db.Packages {
		vulnMap[p.Pkg.Name] = p
	}

	// 4. Scan the SBOM against the Database
	fmt.Println("\n=== VULNERABILITY REPORT ===")
	findingsByPkg := make(map[string]map[string]string)
	matchedPkgs := 0

	for _, installedPkg := range sbom {
		// Does this package have known vulnerabilities in the database?
		if secData, exists := vulnMap[installedPkg.Name]; exists {
			matchedPkgs++

			// Iterate through the versions that contain security fixes
			for fixVersion, cves := range secData.Pkg.Secfixes {
				// APK-aware version comparison: flag package if installed version
				// is older than the known fixed version.
				if matcher.IsVulnerableVersion(installedPkg.Version, fixVersion) {
					if _, ok := findingsByPkg[installedPkg.Name]; !ok {
						findingsByPkg[installedPkg.Name] = make(map[string]string)
					}
					for _, cve := range cves {
						existingFix, seen := findingsByPkg[installedPkg.Name][cve]
						if !seen || matcher.IsVulnerableVersion(fixVersion, existingFix) {
							// Keep the earliest known fix for each CVE.
							findingsByPkg[installedPkg.Name][cve] = fixVersion
						}
					}
				}
			}
		}
	}

	vulnsFound := 0
	pkgNames := make([]string, 0, len(findingsByPkg))
	for pkgName := range findingsByPkg {
		pkgNames = append(pkgNames, pkgName)
	}
	sort.Strings(pkgNames)

	for _, pkgName := range pkgNames {
		cveToFix := findingsByPkg[pkgName]
		if len(cveToFix) == 0 {
			continue
		}

		var installedVersion string
		for _, p := range sbom {
			if p.Name == pkgName {
				installedVersion = p.Version
				break
			}
		}

		cves := make([]string, 0, len(cveToFix))
		earliestFix := ""
		for cve, fix := range cveToFix {
			cves = append(cves, cve)
			if earliestFix == "" || matcher.IsVulnerableVersion(fix, earliestFix) {
				earliestFix = fix
			}
		}
		sort.Strings(cves)

		fmt.Printf("[!] VULNERABILITY FOUND: %s\n", pkgName)
		fmt.Printf("    - Installed Version : %s\n", installedVersion)
		fmt.Printf("    - Earliest Fix In   : %s\n", earliestFix)
		fmt.Printf("    - CVEs              : %s\n\n", strings.Join(cves, ", "))

		vulnsFound += len(cves)
	}

	if vulnsFound == 0 {
		fmt.Println("[✓] No known vulnerabilities found! Your image is clean.")
	} else {
		fmt.Printf("[!] Scan complete. %d unique CVE findings detected.\n", vulnsFound)
	}

	fmt.Println("\n=== SCAN CONTEXT ===")
	fmt.Printf("    - Scanned At (UTC)        : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("    - Installed Packages      : %d\n", len(sbom))
	fmt.Printf("    - SecDB Packages Loaded   : %d\n", len(db.Packages))
	fmt.Printf("    - Packages Matched In DB  : %d\n", matchedPkgs)
	fmt.Printf("    - Vulnerable Packages     : %d\n", len(pkgNames))
	fmt.Printf("    - Unique CVE Findings     : %d\n", vulnsFound)
}

func detectAlpineVersion(imageRef string, sbom []analyzer.Package) (string, error) {
	// Prefer alpine-release; it tracks Alpine OS version directly.
	for _, pkg := range sbom {
		if pkg.Name != "alpine-release" {
			continue
		}

		parts := strings.Split(pkg.Version, ".")
		if len(parts) < 2 {
			return "", fmt.Errorf("package alpine-release has unexpected version format: %s", pkg.Version)
		}
		return parts[0] + "." + parts[1], nil
	}

	// Fallback: parse image reference for tags like alpine:3.14 or alpine:3.14.10.
	if strings.HasPrefix(imageRef, "alpine:") {
		tag := strings.TrimPrefix(imageRef, "alpine:")
		parts := strings.Split(tag, ".")
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1], nil
		}
	}

	return "", fmt.Errorf("could not determine Alpine version (missing alpine-release and unparseable image tag: %s)", imageRef)
}
