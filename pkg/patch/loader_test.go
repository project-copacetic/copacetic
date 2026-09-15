package patch

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/stretchr/testify/assert"
)

// TestDetectLoaderFromBuildkitAddr tests the detectLoaderFromBuildkitAddr function.
func TestDetectLoaderFromBuildkitAddr(t *testing.T) {
	testCases := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "empty address",
			addr:     "",
			expected: "",
		},
		{
			name:     "podman-container scheme",
			addr:     "podman-container://buildx_buildkit_builder0",
			expected: imageloader.Podman,
		},
		{
			name:     "docker-container scheme",
			addr:     "docker-container://buildx_buildkit_builder0",
			expected: imageloader.Docker,
		},
		{
			name:     "docker scheme",
			addr:     "docker://localhost:2375",
			expected: imageloader.Docker,
		},
		{
			name:     "buildx scheme",
			addr:     "buildx://buildx_buildkit_builder0",
			expected: imageloader.Docker,
		},
		{
			name:     "unknown scheme - tcp",
			addr:     "tcp://localhost:1234",
			expected: "",
		},
		{
			name:     "unknown scheme - unix socket",
			addr:     "unix:///var/run/buildkit/buildkitd.sock",
			expected: "",
		},
		{
			name:     "unknown scheme - https",
			addr:     "https://buildkit.example.com:443",
			expected: "",
		},
		{
			name:     "invalid URL format",
			addr:     "not-a-valid-url",
			expected: "",
		},
		{
			name:     "URL with special characters (URL parsing fails)",
			addr:     "docker-container://builder%20name",
			expected: "", // url.Parse might fail on certain special characters
		},
		{
			name:     "scheme only",
			addr:     "podman-container://",
			expected: imageloader.Podman,
		},
		{
			name:     "complex podman URL",
			addr:     "podman-container://buildx_buildkit_builder0?context=rootless",
			expected: imageloader.Podman,
		},
		{
			name:     "complex docker URL with port",
			addr:     "docker://localhost:2376/v1.40",
			expected: imageloader.Docker,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := detectLoaderFromBuildkitAddr(tc.addr)
			assert.Equal(t, tc.expected, result)
		})
	}
}
