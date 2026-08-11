package common

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTrivyDBRepositoriesArePinnedByDigest is a regression guard against accidentally
// reintroducing the floating `:2` tag in the Trivy DB repository configuration. Both
// the primary GHCR and fallback ECR repositories MUST be pinned by sha256 manifest
// digest so integration test runs are reproducible across PRs (see PR #1592).
func TestTrivyDBRepositoriesArePinnedByDigest(t *testing.T) {
	// Each repository entry MUST end with `@sha256:<64-hex-digest>` so a
	// regression to a floating tag like `:2` would fail this assertion.
	digestSuffix := regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	repos := map[string]string{
		"primary":  trivyDBPrimary,
		"fallback": trivyDBFallback,
	}
	for name, repo := range repos {
		t.Run(name, func(t *testing.T) {
			assert.Regexp(t, digestSuffix, repo,
				"%s repository must be pinned by @sha256: digest, not a floating tag", name)
		})
	}

	// trivyDBRepositories is the comma-separated value Trivy actually consumes;
	// confirm both pinned entries flow through unchanged.
	t.Run("composed list", func(t *testing.T) {
		assert.Equal(t, trivyDBPrimary+","+trivyDBFallback, trivyDBRepositories)
		assert.Equal(t, 2, strings.Count(trivyDBRepositories, "@sha256:"),
			"composed --db-repository value must contain exactly two pinned digests")
	})
}

func TestIsTransientScanError(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "unexpected EOF", output: "unexpected EOF", want: true},
		{name: "connection reset", output: "read: connection reset by peer", want: true},
		{name: "deadline exceeded", output: "context deadline exceeded", want: true},
		{name: "cache lock", output: "cache may be in use by another process", want: true},
		{
			name:   "HTTP2 stream canceled by registry",
			output: `remote error: Get "https://mcr.microsoft.com/v2/": stream error: stream ID 1; CANCEL; received from peer`,
			want:   true,
		},
		{name: "non-transient registry error", output: "MANIFEST_UNKNOWN: manifest unknown", want: false},
		{name: "unrelated cancellation", output: "operation CANCEL; received from peer", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isTransientScanError(tt.output))
		})
	}
}
