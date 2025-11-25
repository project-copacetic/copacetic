package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	log "github.com/sirupsen/logrus"
)

// Fetcher handles retrieving SLSA provenance attestations from container registries.
type Fetcher struct{}

// NewFetcher creates a new provenance fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{}
}

// FetchAttestation attempts to fetch SLSA provenance for the given image reference.
func (f *Fetcher) FetchAttestation(ctx context.Context, imageRef string) (*Attestation, error) {
	log.Debugf("Attempting to fetch SLSA provenance for %s", imageRef)

	// Parse image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %s: %w", imageRef, err)
	}

	// Fetch attestations using cosign - try all SLSA predicate types
	slsaTypes := []string{
		"https://slsa.dev/provenance/v1",
		"https://slsa.dev/provenance/v0.2",
		"https://slsa.dev/provenance/v0.1",
		"", // empty string to get all attestations
	}

	for _, predicateType := range slsaTypes {
		attestations, err := cosign.FetchAttestationsForReference(ctx, ref, predicateType, ociremote.WithRemoteOptions())
		if err != nil {
			log.Debugf("Failed to fetch attestations with predicate type %s: %v", predicateType, err)
			continue
		}

		if len(attestations) == 0 {
			continue
		}

		// Parse the first attestation
		for _, att := range attestations {
			// Decode base64 payload
			payloadBytes, err := base64.StdEncoding.DecodeString(att.PayLoad)
			if err != nil {
				log.Debugf("Failed to decode attestation payload: %v", err)
				continue
			}

			parsed, err := f.parseAttestation(payloadBytes)
			if err != nil {
				log.Debugf("Failed to parse attestation: %v", err)
				continue
			}

			if parsed != nil && isSLSAProvenance(parsed.PredicateType) {
				log.Infof("Successfully fetched SLSA provenance for %s (level: %d, type: %s)",
					imageRef, parsed.SLSALevel, parsed.PredicateType)
				return parsed, nil
			}
		}
	}

	return nil, fmt.Errorf("no SLSA provenance found for %s", imageRef)
}

// parseAttestation parses an attestation payload into our Attestation structure.
func (f *Fetcher) parseAttestation(payload []byte) (*Attestation, error) {
	// Parse as in-toto statement
	var statement intoto.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	// Parse predicate
	var predicate map[string]any
	if statement.Predicate != nil {
		predicateJSON, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal predicate: %w", err)
		}
		if err := json.Unmarshal(predicateJSON, &predicate); err != nil {
			return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
		}
	}

	attestation := &Attestation{
		Statement:     &statement,
		Predicate:     predicate,
		PredicateType: statement.PredicateType,
		SLSALevel:     inferSLSALevel(&statement, predicate),
	}

	return attestation, nil
}

// isSLSAProvenance checks if a predicate type is SLSA provenance.
func isSLSAProvenance(predicateType string) bool {
	slsaTypes := []string{
		"https://slsa.dev/provenance/v0.1",
		"https://slsa.dev/provenance/v0.2",
		"https://slsa.dev/provenance/v1",
		"https://slsa.dev/provenance/v1.0",
	}

	for _, t := range slsaTypes {
		if predicateType == t {
			return true
		}
	}
	return false
}

// inferSLSALevel attempts to infer the SLSA level from the provenance.
// This is a simplified heuristic - full verification would require more analysis.
func inferSLSALevel(statement *intoto.Statement, predicate map[string]any) int {
	// Check for builder information
	if predicate == nil {
		return 0
	}

	// SLSA v1.0 structure
	if runDetails, ok := predicate["runDetails"].(map[string]any); ok {
		if builder, ok := runDetails["builder"].(map[string]any); ok {
			if builderID, ok := builder["id"].(string); ok && builderID != "" {
				// If we have a builder ID, assume at least level 2
				return 2
			}
		}
	}

	// SLSA v0.2 structure
	if builder, ok := predicate["builder"].(map[string]any); ok {
		if builderID, ok := builder["id"].(string); ok && builderID != "" {
			return 2
		}
	}

	// If we have materials/dependencies, assume level 1
	if materials, ok := predicate["materials"].([]any); ok && len(materials) > 0 {
		return 1
	}

	return 0
}

// FetchDockerfileFromGitHub fetches a Dockerfile from a GitHub repository at a specific commit.
// This is used as a fallback when SLSA provenance doesn't contain the Dockerfile directly.
func (f *Fetcher) FetchDockerfileFromGitHub(ctx context.Context, repoURL, commit string, dockerfilePaths ...string) (string, error) {
	// Extract owner and repo from URL
	owner, repo, err := parseGitHubRepoURL(repoURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse GitHub repo URL: %w", err)
	}

	// Default Dockerfile paths to try
	paths := dockerfilePaths
	if len(paths) == 0 {
		paths = []string{
			"Dockerfile",
			"build/Dockerfile",
			"docker/Dockerfile",
			"deploy/Dockerfile",
			".docker/Dockerfile",
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Try each path
	for _, path := range paths {
		// Use GitHub raw content API
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, commit, path)
		log.Debugf("Trying to fetch Dockerfile from: %s", rawURL)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			log.Debugf("Failed to create request: %v", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Debugf("Failed to fetch %s: %v", rawURL, err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Debugf("Failed to read response body: %v", err)
				continue
			}
			dockerfile := string(body)
			log.Infof("Successfully fetched Dockerfile from %s/%s @ %s (%s)", owner, repo, commit[:8], path)
			return dockerfile, nil
		}

		resp.Body.Close()
		log.Debugf("Dockerfile not found at %s (status: %d)", path, resp.StatusCode)
	}

	return "", fmt.Errorf("Dockerfile not found in %s/%s at commit %s", owner, repo, commit)
}

// FetchGoModFromGitHub fetches go.mod from a GitHub repository at a specific commit.
// This is useful for understanding module dependencies when rebuilding.
func (f *Fetcher) FetchGoModFromGitHub(ctx context.Context, repoURL, commit string) (string, error) {
	owner, repo, err := parseGitHubRepoURL(repoURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse GitHub repo URL: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/go.mod", owner, repo, commit)
	log.Debugf("Fetching go.mod from: %s", rawURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch go.mod: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("go.mod not found (status: %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read go.mod: %w", err)
	}

	log.Infof("Successfully fetched go.mod from %s/%s @ %s", owner, repo, commit[:8])
	return string(body), nil
}

// parseGitHubRepoURL extracts owner and repo name from a GitHub URL.
// Supports various formats:
//   - https://github.com/owner/repo
//   - github.com/owner/repo
//   - git+https://github.com/owner/repo
func parseGitHubRepoURL(repoURL string) (owner, repo string, err error) {
	// Clean up the URL
	url := repoURL
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "github.com/")
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	// Handle refs in URL (e.g., owner/repo@refs/heads/main)
	if idx := strings.Index(url, "@"); idx != -1 {
		url = url[:idx]
	}

	// Pattern: owner/repo or owner/repo/...
	re := regexp.MustCompile(`^([^/]+)/([^/]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) < 3 {
		return "", "", fmt.Errorf("invalid GitHub repo URL format: %s", repoURL)
	}

	return matches[1], matches[2], nil
}

// EnrichBuildInfoFromGitHub enriches BuildInfo by fetching missing information from GitHub.
// This is called when provenance lacks Dockerfile or other build details.
func (f *Fetcher) EnrichBuildInfoFromGitHub(ctx context.Context, buildInfo *BuildInfo, repoURL, commit string) error {
	parser := NewParser()

	// Fetch and parse Dockerfile if missing
	if buildInfo.Dockerfile == "" {
		dockerfile, err := f.FetchDockerfileFromGitHub(ctx, repoURL, commit)
		if err != nil {
			log.Warnf("Could not fetch Dockerfile from GitHub: %v", err)
		} else {
			buildInfo.Dockerfile = dockerfile
			// Re-analyze Dockerfile to extract build info
			parser.analyzeDockerfile(dockerfile, buildInfo)
			log.Info("Enriched build info with Dockerfile from GitHub")
		}
	}

	// Fetch go.mod to extract module path if missing
	if buildInfo.ModulePath == "" {
		goMod, err := f.FetchGoModFromGitHub(ctx, repoURL, commit)
		if err != nil {
			log.Debugf("Could not fetch go.mod from GitHub: %v", err)
		} else {
			// Extract module path from go.mod
			if modulePath := extractModulePathFromGoMod(goMod); modulePath != "" {
				buildInfo.ModulePath = modulePath
				log.Infof("Enriched build info with module path: %s", modulePath)
			}

			// Extract Go version from go.mod if missing
			if buildInfo.GoVersion == "" {
				if goVersion := extractGoVersionFromGoMod(goMod); goVersion != "" {
					buildInfo.GoVersion = goVersion
					log.Infof("Enriched build info with Go version from go.mod: %s", goVersion)
				}
			}
		}
	}

	// Store source repo info for later use
	buildInfo.BuildArgs["_sourceRepo"] = repoURL
	buildInfo.BuildArgs["_sourceCommit"] = commit

	return nil
}

// extractModulePathFromGoMod extracts the module path from go.mod content.
func extractModulePathFromGoMod(goMod string) string {
	// Pattern: module github.com/owner/repo
	re := regexp.MustCompile(`(?m)^module\s+(\S+)`)
	matches := re.FindStringSubmatch(goMod)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// extractGoVersionFromGoMod extracts the Go version from go.mod content.
func extractGoVersionFromGoMod(goMod string) string {
	// Pattern: go 1.21 or go 1.21.0
	re := regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)`)
	matches := re.FindStringSubmatch(goMod)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}
