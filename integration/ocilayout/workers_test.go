package ocilayout_test

import (
	"strings"
	"testing"

	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
)

// workerPlatforms lists what the BuildKit workers at addr advertise. A failed
// query fails the test: only a successful query may justify skipping a case.
type workerPlatforms []ocispec.Platform

func queryWorkerPlatforms(t *testing.T, addr string) workerPlatforms {
	t.Helper()
	c, err := buildkit.NewClient(t.Context(), buildkit.Opts{Addr: addr})
	require.NoError(t, err, "connect to BuildKit at %s", addr)
	defer c.Close()
	workers, err := c.ListWorkers(t.Context())
	require.NoError(t, err, "query BuildKit worker platforms at %s", addr)
	var advertised workerPlatforms
	for _, worker := range workers {
		if worker != nil {
			advertised = append(advertised, worker.Platforms...)
		}
	}
	require.NotEmpty(t, advertised, "BuildKit at %s advertises no worker platforms", addr)
	return advertised
}

// supports applies the same rule Copa uses before patching a platform.
func (advertised workerPlatforms) supports(target *ocispec.Platform) bool {
	normalized := platforms.Normalize(*target)
	for _, platform := range advertised {
		if platforms.Only(platforms.Normalize(platform)).Match(normalized) {
			return true
		}
	}
	return false
}

func (advertised workerPlatforms) String() string {
	formatted := make([]string, 0, len(advertised))
	for _, platform := range advertised {
		formatted = append(formatted, platforms.Format(platform))
	}
	return strings.Join(formatted, ", ")
}
