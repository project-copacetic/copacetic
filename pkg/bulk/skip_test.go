package bulk

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverExistingPatchTags(t *testing.T) {
	tests := []struct {
		name        string
		repo        string
		baseTag     string
		allTags     []string
		expected    []string
		expectError bool
	}{
		{
			name:     "no matching tags",
			repo:     "registry.io/nginx",
			baseTag:  "1.25.3-patched",
			allTags:  []string{"1.25.3", "1.25.2-patched", "latest"},
			expected: []string{},
		},
		{
			name:     "only base tag exists",
			repo:     "registry.io/nginx",
			baseTag:  "1.25.3-patched",
			allTags:  []string{"1.25.3", "1.25.3-patched", "latest"},
			expected: []string{"1.25.3-patched"},
		},
		{
			name:     "base tag and versioned tags",
			repo:     "registry.io/nginx",
			baseTag:  "1.25.3-patched",
			allTags:  []string{"1.25.3", "1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-2", "latest"},
			expected: []string{"1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-2"},
		},
		{
			name:     "only versioned tags (no base)",
			repo:     "registry.io/nginx",
			baseTag:  "1.25.3-patched",
			allTags:  []string{"1.25.3", "1.25.3-patched-1", "1.25.3-patched-3", "latest"},
			expected: []string{"1.25.3-patched-1", "1.25.3-patched-3"},
		},
		{
			name:     "tags sorted by version number",
			repo:     "registry.io/nginx",
			baseTag:  "1.25.3-patched",
			allTags:  []string{"1.25.3-patched-10", "1.25.3-patched-2", "1.25.3-patched-1", "1.25.3-patched"},
			expected: []string{"1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-2", "1.25.3-patched-10"},
		},
		{
			name:     "custom template with special chars",
			repo:     "registry.io/nginx",
			baseTag:  "1.25.3-fixed",
			allTags:  []string{"1.25.3-fixed", "1.25.3-fixed-1", "1.25.3-patched"},
			expected: []string{"1.25.3-fixed", "1.25.3-fixed-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock listAllTags
			oldListAllTags := listAllTags
			defer func() { listAllTags = oldListAllTags }()
			listAllTags = func(repo name.Repository) ([]string, error) {
				return tt.allTags, nil
			}

			result, err := discoverExistingPatchTags(tt.repo, tt.baseTag)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if len(tt.expected) == 0 {
					assert.Empty(t, result)
				} else {
					assert.Equal(t, tt.expected, result)
				}
			}
		})
	}
}

func TestDiscoverExistingPatchTags_ArchSuffixesExcluded(t *testing.T) {
	tests := []struct {
		name     string
		baseTag  string
		allTags  []string
		expected []string
	}{
		{
			name:     "386 arch tag excluded (numeric arch collision)",
			baseTag:  "3.18.0-patched",
			allTags:  []string{"3.18.0-patched", "3.18.0-patched-386", "3.18.0-patched-amd64", "3.18.0-patched-arm64"},
			expected: []string{"3.18.0-patched"},
		},
		{
			name:     "versioned patch tag kept alongside arch tags",
			baseTag:  "3.18.0-patched",
			allTags:  []string{"3.18.0-patched", "3.18.0-patched-1", "3.18.0-patched-386", "3.18.0-patched-arm64"},
			expected: []string{"3.18.0-patched", "3.18.0-patched-1"},
		},
		{
			name:    "all known arch suffixes excluded",
			baseTag: "1.0.0-patched",
			allTags: []string{
				"1.0.0-patched",
				"1.0.0-patched-386",
				"1.0.0-patched-amd64",
				"1.0.0-patched-arm",
				"1.0.0-patched-arm-v5",
				"1.0.0-patched-arm-v6",
				"1.0.0-patched-arm-v7",
				"1.0.0-patched-arm64",
				"1.0.0-patched-arm64-v8",
				"1.0.0-patched-ppc64le",
				"1.0.0-patched-s390x",
				"1.0.0-patched-riscv64",
			},
			expected: []string{"1.0.0-patched"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldListAllTags := listAllTags
			defer func() { listAllTags = oldListAllTags }()
			listAllTags = func(repo name.Repository) ([]string, error) {
				return tt.allTags, nil
			}

			result, err := discoverExistingPatchTags("registry.io/alpine", tt.baseTag)
			require.NoError(t, err)
			if len(tt.expected) == 0 {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestIsArchSpecificTag(t *testing.T) {
	tests := []struct {
		tag      string
		baseTag  string
		expected bool
	}{
		{"3.18.0-patched-386", "3.18.0-patched", true},
		{"3.18.0-patched-amd64", "3.18.0-patched", true},
		{"3.18.0-patched-arm64", "3.18.0-patched", true},
		{"3.18.0-patched-arm", "3.18.0-patched", true},
		{"3.18.0-patched-arm-v7", "3.18.0-patched", true},
		{"3.18.0-patched-ppc64le", "3.18.0-patched", true},
		{"3.18.0-patched-s390x", "3.18.0-patched", true},
		{"3.18.0-patched-riscv64", "3.18.0-patched", true},
		// These are NOT arch tags — they should be treated as version tags
		{"3.18.0-patched-1", "3.18.0-patched", false},
		{"3.18.0-patched-10", "3.18.0-patched", false},
		{"3.18.0-patched", "3.18.0-patched", false},
		// Wrong base tag
		{"3.18.0-patched-386", "3.18.0-fixed", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag+"_base_"+tt.baseTag, func(t *testing.T) {
			result := isArchSpecificTag(tt.tag, tt.baseTag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDiscoverExistingPatchTags_RegistryError(t *testing.T) {
	// Mock listAllTags to return an error
	oldListAllTags := listAllTags
	defer func() { listAllTags = oldListAllTags }()
	listAllTags = func(repo name.Repository) ([]string, error) {
		return nil, fmt.Errorf("registry auth failed")
	}

	result, err := discoverExistingPatchTags("registry.io/nginx", "1.25.3-patched")
	// Should fail-open and return empty list with no error
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestLatestPatchTag(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		baseTag  string
		expected string
	}{
		{
			name:     "empty list",
			tags:     []string{},
			baseTag:  "1.25.3-patched",
			expected: "",
		},
		{
			name:     "single base tag",
			tags:     []string{"1.25.3-patched"},
			baseTag:  "1.25.3-patched",
			expected: "1.25.3-patched",
		},
		{
			name:     "multiple versioned tags",
			tags:     []string{"1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-2"},
			baseTag:  "1.25.3-patched",
			expected: "1.25.3-patched-2",
		},
		{
			name:     "only versioned tags",
			tags:     []string{"1.25.3-patched-1", "1.25.3-patched-5"},
			baseTag:  "1.25.3-patched",
			expected: "1.25.3-patched-5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := latestPatchTag(tt.tags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNextPatchTag(t *testing.T) {
	tests := []struct {
		name         string
		baseTag      string
		existingTags []string
		expected     string
	}{
		{
			name:         "no existing tags",
			baseTag:      "1.25.3-patched",
			existingTags: []string{},
			expected:     "1.25.3-patched",
		},
		{
			name:         "only base tag exists",
			baseTag:      "1.25.3-patched",
			existingTags: []string{"1.25.3-patched"},
			expected:     "1.25.3-patched-1",
		},
		{
			name:         "base and version-1",
			baseTag:      "1.25.3-patched",
			existingTags: []string{"1.25.3-patched", "1.25.3-patched-1"},
			expected:     "1.25.3-patched-2",
		},
		{
			name:         "highest version is 3",
			baseTag:      "1.25.3-patched",
			existingTags: []string{"1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-3"},
			expected:     "1.25.3-patched-4",
		},
		{
			name:         "only versioned tags (no base)",
			baseTag:      "1.25.3-patched",
			existingTags: []string{"1.25.3-patched-2", "1.25.3-patched-5"},
			expected:     "1.25.3-patched-6",
		},
		{
			name:         "custom template",
			baseTag:      "1.25.3-fixed",
			existingTags: []string{"1.25.3-fixed", "1.25.3-fixed-1"},
			expected:     "1.25.3-fixed-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nextPatchTag(tt.baseTag, tt.existingTags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractVersionNumber(t *testing.T) {
	tests := []struct {
		tag      string
		baseTag  string
		expected int
	}{
		{"1.25.3-patched", "1.25.3-patched", 0},
		{"1.25.3-patched-1", "1.25.3-patched", 1},
		{"1.25.3-patched-10", "1.25.3-patched", 10},
		{"1.25.3-patched-100", "1.25.3-patched", 100},
		{"invalid-tag", "1.25.3-patched", 0},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			result := extractVersionNumber(tt.tag, tt.baseTag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckReportForVulnerabilities(t *testing.T) {
	t.Run("function signature", func(t *testing.T) {
		// Verify the function is callable
		assert.NotNil(t, checkReportForVulnerabilities)
	})
}

func TestBuildReportIndex(t *testing.T) {
	// Create a temporary directory for test reports
	tmpDir := t.TempDir()

	// Create test report files
	report1 := `{"ArtifactName": "alpine:3.14.0", "Results": []}`
	report2 := `{"ArtifactName": "registry.io/nginx:1.25.3-patched", "Results": []}`
	report3 := `{"ArtifactName": "quay.io/prometheus/alertmanager:v0.28.1", "Results": []}`
	invalidJSON := `{invalid json`
	noArtifact := `{"Results": []}`

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "alpine.json"), []byte(report1), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "nginx.json"), []byte(report2), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "prometheus.json"), []byte(report3), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.json"), []byte(invalidJSON), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "no-artifact.json"), []byte(noArtifact), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "not-json.txt"), []byte("text file"), 0o600))

	// Build the index
	idx := buildReportIndex(tmpDir)

	// Verify the index was built correctly
	assert.NotNil(t, idx)
	assert.NotNil(t, idx.refs)

	// Check that valid reports were indexed (3 valid reports)
	assert.Equal(t, 3, len(idx.refs), "Should index 3 valid reports")

	// Verify specific entries (normalized references)
	_, found := idx.refs["index.docker.io/library/alpine:3.14.0"]
	assert.True(t, found, "Should find alpine report")

	_, found = idx.refs["registry.io/nginx:1.25.3-patched"]
	assert.True(t, found, "Should find nginx report")

	_, found = idx.refs["quay.io/prometheus/alertmanager:v0.28.1"]
	assert.True(t, found, "Should find prometheus report")

	// Verify invalid files were not indexed
	assert.Equal(t, 3, len(idx.refs), "Should only have 3 entries (invalid files skipped)")
}

func TestReportIndexLookup(t *testing.T) {
	tests := []struct {
		name        string
		indexRefs   map[string]string
		lookupRef   string
		expectFound bool
		expectPath  string
	}{
		{
			name: "exact match",
			indexRefs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/nginx.json",
			},
			lookupRef:   "registry.io/nginx:1.25.3-patched",
			expectFound: true,
			expectPath:  "/tmp/reports/nginx.json",
		},
		{
			name: "short form lookup matches normalized docker.io",
			indexRefs: map[string]string{
				"index.docker.io/library/nginx:1.25.3": "/tmp/reports/nginx.json",
			},
			lookupRef:   "nginx:1.25.3",
			expectFound: true,
			expectPath:  "/tmp/reports/nginx.json",
		},
		{
			name: "full docker.io matches short form",
			indexRefs: map[string]string{
				"index.docker.io/library/nginx:1.25.3": "/tmp/reports/nginx.json",
			},
			lookupRef:   "docker.io/library/nginx:1.25.3",
			expectFound: true,
			expectPath:  "/tmp/reports/nginx.json",
		},
		{
			name: "custom registry exact match",
			indexRefs: map[string]string{
				"quay.io/prometheus/alertmanager:v0.28.1": "/tmp/reports/alertmanager.json",
			},
			lookupRef:   "quay.io/prometheus/alertmanager:v0.28.1",
			expectFound: true,
			expectPath:  "/tmp/reports/alertmanager.json",
		},
		{
			name: "not found in index",
			indexRefs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/nginx.json",
			},
			lookupRef:   "registry.io/alpine:3.19",
			expectFound: false,
		},
		{
			name:        "nil index",
			indexRefs:   nil,
			lookupRef:   "nginx:1.25.3",
			expectFound: false,
		},
		{
			name:        "empty index",
			indexRefs:   map[string]string{},
			lookupRef:   "nginx:1.25.3",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var idx *reportIndex
			if tt.indexRefs != nil {
				idx = &reportIndex{refs: tt.indexRefs}
			}

			path, found := idx.lookup(tt.lookupRef)

			assert.Equal(t, tt.expectFound, found, "Found mismatch")
			if tt.expectFound {
				assert.Equal(t, tt.expectPath, path, "Path mismatch")
			}
		})
	}
}

func TestEvaluatePatchAction(t *testing.T) {
	tests := []struct {
		name             string
		repo             string
		baseTag          string
		scanner          string
		reports          *reportIndex
		existingTags     []string
		reportResult     bool // true = has vulns, false = no vulns
		reportError      error
		listTagsError    error
		expectedSkip     bool
		expectedReason   string
		expectedResolved string
	}{
		{
			name:             "no existing patched tags",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          &reportIndex{refs: map[string]string{}},
			existingTags:     []string{},
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched",
		},
		{
			name:    "existing tag, no vulnerabilities",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportResult:     false, // no vulns
			expectedSkip:     true,
			expectedReason:   "no fixable vulnerabilities",
			expectedResolved: "1.25.3-patched",
		},
		{
			name:    "existing tag, has vulnerabilities",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportResult:     true, // has vulns
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched-1",
		},
		{
			name:    "existing tag, report parse error",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportError:      fmt.Errorf("invalid JSON"),
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched-1",
		},
		{
			name:             "existing tag, report not found in index",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          &reportIndex{refs: map[string]string{}}, // empty index
			existingTags:     []string{"1.25.3-patched"},
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched-1",
		},
		{
			name:             "registry tag listing fails",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          &reportIndex{refs: map[string]string{}},
			listTagsError:    fmt.Errorf("auth error"),
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched", // fail-open to base tag
		},
		{
			name:             "no reports index provided",
			repo:             "registry.io/nginx",
			baseTag:          "1.25.3-patched",
			scanner:          "trivy",
			reports:          nil, // nil index
			existingTags:     []string{"1.25.3-patched"},
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched-1",
		},
		{
			name:    "multiple existing versions, no vulnerabilities",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched-2": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-2"},
			reportResult:     false,
			expectedSkip:     true,
			expectedReason:   "no fixable vulnerabilities",
			expectedResolved: "1.25.3-patched-2", // latest tag
		},
		{
			name:    "multiple existing versions, has vulnerabilities",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "trivy",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched-2": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched", "1.25.3-patched-1", "1.25.3-patched-2"},
			reportResult:     true,
			expectedSkip:     false,
			expectedResolved: "1.25.3-patched-3", // next version
		},
		{
			name:    "custom scanner supported",
			repo:    "registry.io/nginx",
			baseTag: "1.25.3-patched",
			scanner: "native",
			reports: &reportIndex{refs: map[string]string{
				"registry.io/nginx:1.25.3-patched": "/tmp/reports/report1.json",
			}},
			existingTags:     []string{"1.25.3-patched"},
			reportResult:     false,
			expectedSkip:     true,
			expectedReason:   "no fixable vulnerabilities",
			expectedResolved: "1.25.3-patched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock listAllTags
			oldListAllTags := listAllTags
			defer func() { listAllTags = oldListAllTags }()
			listAllTags = func(repo name.Repository) ([]string, error) {
				if tt.listTagsError != nil {
					return nil, tt.listTagsError
				}
				// Return the existing tags plus some unrelated tags
				allTags := append([]string{"latest", "1.25.2"}, tt.existingTags...)
				return allTags, nil
			}

			// Mock checkReportForVulnerabilities
			oldCheck := checkReportForVulnerabilities
			defer func() { checkReportForVulnerabilities = oldCheck }()
			checkCalled := false
			checkReportForVulnerabilities = func(reportPath, scanner, pkgTypes, libraryPatchLevel string) (bool, error) {
				checkCalled = true
				if tt.reportError != nil {
					return false, tt.reportError
				}
				return tt.reportResult, nil
			}

			result := evaluatePatchAction(tt.repo, tt.baseTag, tt.scanner, tt.reports, "os", "patch")

			assert.Equal(t, tt.expectedSkip, result.ShouldSkip, "ShouldSkip mismatch")
			assert.Equal(t, tt.expectedReason, result.Reason, "Reason mismatch")
			assert.Equal(t, tt.expectedResolved, result.ResolvedTag, "ResolvedTag mismatch")

			// Verify check was only called when expected
			if len(tt.existingTags) == 0 || tt.reports == nil || tt.listTagsError != nil {
				assert.False(t, checkCalled, "Report check should not have been called")
			} else {
				// Check was called only if report was found
				latestTag := latestPatchTag(tt.existingTags)
				imageRef := fmt.Sprintf("%s:%s", tt.repo, latestTag)
				_, found := tt.reports.lookup(imageRef)
				assert.Equal(t, found, checkCalled, "Report check call mismatch")
			}
		})
	}
}
