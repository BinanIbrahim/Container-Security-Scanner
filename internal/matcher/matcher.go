// internal/matcher/matcher.go
package matcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SecDB represents the root structure of the Alpine Security Database JSON.
type SecDB struct {
	Packages []SecPackage `json:"packages"`
}

// SecPackage represents a single package's vulnerability data in the SecDB.
type SecPackage struct {
	Pkg struct {
		Name string `json:"name"`
		// Secfixes maps a version string (the version that FIXES the vulnerability)
		// to a list of CVE IDs.
		Secfixes map[string][]string `json:"secfixes"`
	} `json:"pkg"`
}

// FetchSecDB downloads and merges Alpine vulnerability databases for a specific Alpine version.
// We combine both main and community repositories to improve coverage.
func FetchSecDB(alpineVersion string) (*SecDB, error) {
	// We use a custom HTTP client with a strict timeout so our agent never hangs forever
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return fetchSecDBFromBase(client, "https://secdb.alpinelinux.org", alpineVersion)
}

func fetchSecDBFromBase(client *http.Client, baseURL, alpineVersion string) (*SecDB, error) {
	repos := []string{"main", "community"}
	mergedByPkg := make(map[string]SecPackage)
	baseURL = strings.TrimRight(baseURL, "/")

	for _, repo := range repos {
		url := fmt.Sprintf("%s/v%s/%s.json", baseURL, alpineVersion, repo)
		fmt.Printf("Downloading vulnerability database from: %s\n", url)

		db, err := fetchSingleSecDB(client, url)
		if err != nil {
			return nil, err
		}

		for _, p := range db.Packages {
			existing, ok := mergedByPkg[p.Pkg.Name]
			if !ok {
				mergedByPkg[p.Pkg.Name] = p
				continue
			}

			if existing.Pkg.Secfixes == nil {
				existing.Pkg.Secfixes = make(map[string][]string)
			}
			for fixVersion, cves := range p.Pkg.Secfixes {
				existing.Pkg.Secfixes[fixVersion] = cves
			}
			mergedByPkg[p.Pkg.Name] = existing
		}
	}

	merged := &SecDB{
		Packages: make([]SecPackage, 0, len(mergedByPkg)),
	}
	for _, p := range mergedByPkg {
		merged.Packages = append(merged.Packages, p)
	}

	return merged, nil
}

func fetchSingleSecDB(client *http.Client, url string) (*SecDB, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SecDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SecDB returned non-200 status: %d", resp.StatusCode)
	}

	var db SecDB
	if err := json.NewDecoder(resp.Body).Decode(&db); err != nil {
		return nil, fmt.Errorf("failed to decode SecDB JSON: %w", err)
	}

	return &db, nil
}
