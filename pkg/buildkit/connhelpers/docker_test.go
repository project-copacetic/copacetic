package connhelpers

import (
	"os"
	"testing"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
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
				os.Setenv("DOCKER_HOST", tt.envDockerHost)
			} else {
				os.Unsetenv("DOCKER_HOST")
			}

			_, err := getDockerTransport(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDockerTransport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
