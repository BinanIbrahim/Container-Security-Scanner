package matcher

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSecDBFromBase_MergesMainAndCommunity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3.14/main.json":
			_, _ = w.Write([]byte(`{
				"packages": [
					{"pkg": {"name": "musl", "secfixes": {"1.2.2-r5": ["CVE-1"]}}},
					{"pkg": {"name": "busybox", "secfixes": {"1.34.0-r0": ["CVE-2"]}}}
				]
			}`))
		case "/v3.14/community.json":
			_, _ = w.Write([]byte(`{
				"packages": [
					{"pkg": {"name": "musl", "secfixes": {"1.2.2-r6": ["CVE-3"]}}},
					{"pkg": {"name": "libretls", "secfixes": {"3.5.1-r0": ["CVE-4"]}}}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	db, err := fetchSecDBFromBase(client, server.URL, "3.14")
	if err != nil {
		t.Fatalf("fetchSecDBFromBase returned unexpected error: %v", err)
	}

	byName := map[string]SecPackage{}
	for _, p := range db.Packages {
		byName[p.Pkg.Name] = p
	}

	if len(byName) != 3 {
		t.Fatalf("expected 3 merged packages, got %d", len(byName))
	}

	musl, ok := byName["musl"]
	if !ok {
		t.Fatalf("expected musl package in merged results")
	}
	if len(musl.Pkg.Secfixes) != 2 {
		t.Fatalf("expected musl secfixes from both repos, got %d entries", len(musl.Pkg.Secfixes))
	}
	if _, ok := musl.Pkg.Secfixes["1.2.2-r5"]; !ok {
		t.Fatalf("expected musl secfix version 1.2.2-r5 from main repo")
	}
	if _, ok := musl.Pkg.Secfixes["1.2.2-r6"]; !ok {
		t.Fatalf("expected musl secfix version 1.2.2-r6 from community repo")
	}
}

func TestFetchSecDBFromBase_ReturnsErrorOnNon200(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3.14/main.json":
			_, _ = w.Write([]byte(`{"packages":[]}`))
		case "/v3.14/community.json":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	_, err := fetchSecDBFromBase(client, server.URL, "3.14")
	if err == nil {
		t.Fatal("expected error when one repo returns non-200, got nil")
	}
}
