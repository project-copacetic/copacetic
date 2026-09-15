package connhelpers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocker(t *testing.T) {
	_, err := connhelper.GetConnectionHelper("docker://")
	assert.NoError(t, err)
}

func TestGetDockerTransport(t *testing.T) {
	tests := []struct {
		name          string
		addr          string
		envDockerHost string
		wantErr       bool
	}{
		{
			name:          "Empty addr, DOCKER_HOST env set",
			addr:          "",
			envDockerHost: "unix:///var/run/docker.sock",
			wantErr:       false,
		},
		{
			name:    "Non-empty addr",
			addr:    "tcp://localhost:2375",
			wantErr: false,
		},
		{
			name:    "invalid addr",
			addr:    "1234://this/is/not/real:at-all-",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set DOCKER_HOST environment variable if specified in the test case
			if tt.envDockerHost != "" {
				t.Setenv("DOCKER_HOST", tt.envDockerHost)
			} else {
				if v, ok := os.LookupEnv("DOCKER_HOST"); ok {
					os.Unsetenv("DOCKER_HOST")
					t.Cleanup(func() {
						os.Setenv("DOCKER_HOST", v) // Restore original value after test
					})
				}
			}

			_, err := getDockerTransport(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDockerTransport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAddrFromContext(t *testing.T) {
	type Endpoint struct {
		Host string `json:"Host"`
	}

	type contextInfo struct {
		Name      string              `json:"Name"`
		Endpoinds map[string]Endpoint `json:"Endpoints"`
	}

	writeContext := func(t *testing.T, info contextInfo) {
		configDir := os.Getenv("DOCKER_CONFIG")
		contextsDir := filepath.Join(configDir, "contexts", "meta")
		err := os.MkdirAll(contextsDir, 0o755)
		require.NoError(t, err)

		// Docker uses the digest of the context name as the directory name
		id := digest.FromString(info.Name).Encoded()
		dir := filepath.Join(contextsDir, id)
		err = os.MkdirAll(dir, 0o755)
		require.NoError(t, err)

		dt, err := json.Marshal(info)
		require.NoError(t, err)

		p := filepath.Join(dir, "meta.json")
		err = os.WriteFile(filepath.Join(dir, "meta.json"), dt, 0o600)
		require.NoError(t, err)
		t.Log("wrote context file", p)
	}

	newInfo := func(name string) contextInfo {
		return contextInfo{
			Name: name,
			Endpoinds: map[string]Endpoint{
				"docker": {
					Host: fmt.Sprintf("tcp://%s:2375", name),
				},
			},
		}
	}

	setupDockerConfig := func(t *testing.T) {
		// Make the docker CLI reads the config from a temp dir
		// so we can setup a fake context
		dir := t.TempDir()

		// Make docker read the config from the temp dir
		t.Setenv("DOCKER_CONFIG", dir)
		t.Setenv("DOCKER_CONTEXT", "") // Make sure DOCKER_CONTEXT isn't leaked into our env

		writeContext(t, newInfo("test1"))
		writeContext(t, newInfo("test2"))
	}

	setContextConfig := func(t *testing.T, name string) {
		p := filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json")
		err := os.WriteFile(p, []byte(fmt.Sprintf(`{"currentContext": "%s"}`, name)), 0o600)
		require.NoError(t, err)
	}

	setupDockerConfig(t)

	t.Run("default context", func(t *testing.T) {
		addr, err := AddrFromDockerContext()
		require.NoError(t, err)
		assert.Equal(t, "unix:///var/run/docker.sock", addr)
	})

	t.Run("context selected in env overrides config", func(t *testing.T) {
		t.Run("set config", func(t *testing.T) {
			setContextConfig(t, "test1")

			addr, err := AddrFromDockerContext()
			require.NoError(t, err)
			assert.Equal(t, "tcp://test1:2375", addr)
		})

		t.Run("set env", func(t *testing.T) {
			setContextConfig(t, "test1") // Use test1 in the docker context still

			// Use os.Setenv here because t.Setenv has already been called in setupDockerConfig
			os.Setenv("DOCKER_CONTEXT", "test2") // Override with test2

			addr, err := AddrFromDockerContext()
			require.NoError(t, err)
			assert.Equal(t, "tcp://test2:2375", addr) // Check the test2 address
		})
	})
}
