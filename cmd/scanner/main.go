package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"sentinel-scanner/internal/analyzer"
	"sentinel-scanner/internal/extractor"
	"sentinel-scanner/internal/matcher"
)

type PackageFinding struct {
	PackageName      string
	InstalledVersion string
	EarliestFix      string
	CVEs             []string
	RiskScore        int
	Severity         string
	Remediation      string
}

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
	installedVersions := make(map[string]string, len(sbom))
	matchedPkgs := 0

	for _, installedPkg := range sbom {
		installedVersions[installedPkg.Name] = installedPkg.Version

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

	reportFindings := make([]PackageFinding, 0, len(pkgNames))
	for _, pkgName := range pkgNames {
		cveToFix := findingsByPkg[pkgName]
		if len(cveToFix) == 0 {
			continue
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

		score := calculateRiskScore(len(cves))
		severity := classifySeverity(score)
		remediation := buildRemediation(pkgName, earliestFix)

		reportFinding := PackageFinding{
			PackageName:      pkgName,
			InstalledVersion: installedVersions[pkgName],
			EarliestFix:      earliestFix,
			CVEs:             cves,
			RiskScore:        score,
			Severity:         severity,
			Remediation:      remediation,
		}
		reportFindings = append(reportFindings, reportFinding)

		fmt.Printf("[!] VULNERABILITY FOUND: %s\n", reportFinding.PackageName)
		fmt.Printf("    - Installed Version : %s\n", reportFinding.InstalledVersion)
		fmt.Printf("    - Earliest Fix In   : %s\n", earliestFix)
		fmt.Printf("    - Severity          : %s (score: %d/100)\n", reportFinding.Severity, reportFinding.RiskScore)
		fmt.Printf("    - CVEs              : %s\n\n", strings.Join(cves, ", "))
		fmt.Printf("    - Remediation       : %s\n\n", reportFinding.Remediation)

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
	fmt.Printf("    - Highest Severity        : %s\n", highestSeverity(reportFindings))
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

func calculateRiskScore(cveCount int) int {
	if cveCount <= 0 {
		return 0
	}

	// Cap near 100 while keeping small sets of CVEs differentiated.
	score := int(math.Round(100 * (1 - math.Exp(-0.35*float64(cveCount)))))
	if score > 100 {
		return 100
	}
	return score
}

func classifySeverity(score int) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 70:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func buildRemediation(pkgName, earliestFix string) string {
	return fmt.Sprintf("Upgrade %s to version %s or newer, then rebuild and redeploy the image.", pkgName, earliestFix)
}

func highestSeverity(findings []PackageFinding) string {
	maxScore := 0
	for _, finding := range findings {
		if finding.RiskScore > maxScore {
			maxScore = finding.RiskScore
		}
	}
	return classifySeverity(maxScore)
}
