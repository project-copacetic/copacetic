package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions(t *testing.T) {
	t.Run("Default values", func(t *testing.T) {
		opts := Options{}

		assert.Empty(t, opts.Image)
		assert.Empty(t, opts.Report)
		assert.Empty(t, opts.PatchedTag)
		assert.Empty(t, opts.Suffix)
		assert.Empty(t, opts.WorkingFolder)
		assert.Zero(t, opts.Timeout)
		assert.Empty(t, opts.Scanner)
		assert.False(t, opts.IgnoreError)
		assert.Empty(t, opts.Format)
		assert.Empty(t, opts.Output)
		assert.Zero(t, opts.Progress)
		assert.Empty(t, opts.BkAddr)
		assert.Empty(t, opts.BkCACertPath)
		assert.Empty(t, opts.BkCertPath)
		assert.Empty(t, opts.BkKeyPath)
		assert.False(t, opts.Push)
		assert.Empty(t, opts.Platforms)
		assert.Empty(t, opts.Loader)
		assert.Empty(t, opts.OutputContext)
	})

	t.Run("Populated options", func(t *testing.T) {
		opts := Options{
			Image:      "registry.io/image:tag",
			Report:     "/path/to/report.json",
			PatchedTag: "registry.io/image:patched",
			Suffix:     "-patched",

			WorkingFolder: "/tmp/copa-work",
			Timeout:       5 * time.Minute,

			Scanner:     "trivy",
			IgnoreError: true,

			Format:   "oci",
			Output:   "/tmp/output",
			Progress: progressui.DisplayMode("auto"),

			BkAddr:       "tcp://buildkit:1234",
			BkCACertPath: "/certs/ca.pem",
			BkCertPath:   "/certs/cert.pem",
			BkKeyPath:    "/certs/key.pem",

			Push:      true,
			Platforms: []string{"linux/amd64", "linux/arm64"},
			Loader:    "docker",

			OutputContext: "/tmp/context",
		}

		assert.Equal(t, "registry.io/image:tag", opts.Image)
		assert.Equal(t, "/path/to/report.json", opts.Report)
		assert.Equal(t, "registry.io/image:patched", opts.PatchedTag)
		assert.Equal(t, "-patched", opts.Suffix)
		assert.Equal(t, "/tmp/copa-work", opts.WorkingFolder)
		assert.Equal(t, 5*time.Minute, opts.Timeout)
		assert.Equal(t, "trivy", opts.Scanner)
		assert.True(t, opts.IgnoreError)
		assert.Equal(t, "oci", opts.Format)
		assert.Equal(t, "/tmp/output", opts.Output)
		assert.Equal(t, progressui.DisplayMode("auto"), opts.Progress)
		assert.Equal(t, "tcp://buildkit:1234", opts.BkAddr)
		assert.Equal(t, "/certs/ca.pem", opts.BkCACertPath)
		assert.Equal(t, "/certs/cert.pem", opts.BkCertPath)
		assert.Equal(t, "/certs/key.pem", opts.BkKeyPath)
		assert.True(t, opts.Push)
		assert.Equal(t, []string{"linux/amd64", "linux/arm64"}, opts.Platforms)
		assert.Equal(t, "docker", opts.Loader)
		assert.Equal(t, "/tmp/context", opts.OutputContext)
	})

	t.Run("JSON marshaling", func(t *testing.T) {
		opts := Options{
			Image:         "test-image",
			Report:        "test-report.json",
			PatchedTag:    "test-patched",
			WorkingFolder: "/tmp/test",
			Timeout:       30 * time.Second,
			Scanner:       "trivy",
			IgnoreError:   true,
			Push:          false,
			Platforms:     []string{"linux/amd64"},
		}

		data, err := json.Marshal(opts)
		require.NoError(t, err)

		var unmarshaled Options
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, opts.Image, unmarshaled.Image)
		assert.Equal(t, opts.Report, unmarshaled.Report)
		assert.Equal(t, opts.PatchedTag, unmarshaled.PatchedTag)
		assert.Equal(t, opts.WorkingFolder, unmarshaled.WorkingFolder)
		assert.Equal(t, opts.Timeout, unmarshaled.Timeout)
		assert.Equal(t, opts.Scanner, unmarshaled.Scanner)
		assert.Equal(t, opts.IgnoreError, unmarshaled.IgnoreError)
		assert.Equal(t, opts.Push, unmarshaled.Push)
		assert.Equal(t, opts.Platforms, unmarshaled.Platforms)
	})

	t.Run("Empty platforms slice", func(t *testing.T) {
		opts := Options{
			Platforms: []string{},
		}

		assert.NotNil(t, opts.Platforms)
		assert.Len(t, opts.Platforms, 0)
	})

	t.Run("Nil platforms slice", func(t *testing.T) {
		opts := Options{
			Platforms: nil,
		}

		assert.Nil(t, opts.Platforms)
	})

	t.Run("BuildKit cert paths", func(t *testing.T) {
		opts := Options{
			BkCACertPath: "/ca.pem",
			BkCertPath:   "/cert.pem",
			BkKeyPath:    "/key.pem",
		}

		// Test that all cert paths are properly set
		assert.Equal(t, "/ca.pem", opts.BkCACertPath)
		assert.Equal(t, "/cert.pem", opts.BkCertPath)
		assert.Equal(t, "/key.pem", opts.BkKeyPath)

		// Test cert paths in combination with BkAddr
		opts.BkAddr = "tcp://buildkit:1234"
		assert.Equal(t, "tcp://buildkit:1234", opts.BkAddr)
	})

	t.Run("Progress display modes", func(t *testing.T) {
		testCases := []progressui.DisplayMode{
			progressui.AutoMode,
			progressui.PlainMode,
			progressui.TtyMode,
		}

		for _, mode := range testCases {
			opts := Options{Progress: mode}
			assert.Equal(t, mode, opts.Progress)
		}
	})

	t.Run("Timeout edge cases", func(t *testing.T) {
		// Zero timeout
		opts1 := Options{Timeout: 0}
		assert.Zero(t, opts1.Timeout)

		// Very long timeout
		opts2 := Options{Timeout: 24 * time.Hour}
		assert.Equal(t, 24*time.Hour, opts2.Timeout)

		// Negative timeout (though this shouldn't happen in practice)
		opts3 := Options{Timeout: -1 * time.Second}
		assert.Equal(t, -1*time.Second, opts3.Timeout)
	})
}
