package connhelpers

import (
	"os"
	"testing"

	"github.com/cpuguy83/go-docker/transport"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
)

func TestDocker(t *testing.T) {
	_, err := connhelper.GetConnectionHelper("docker://")
	assert.NoError(t, err)
}

func TestGetDockerTransport(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		want  transport.Transport
		want1 bool
	}{
		{
			name:  "Empty addr and DOCKER_HOST unset",
			addr:  "",
			want:  transport.Transport{},
			want1: false,
		},
		{
			name:  "Empty addr and DOCKER_HOST set",
			addr:  "",
			want:  transport.Transport{},
			want1: false,
		},
		{
			name:  "Addr set",
			addr:  "tcp://localhost:2375", // Replace with appropriate test addr
			want:  transport.Transport{},
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Empty addr and DOCKER_HOST set" {
				os.Setenv("DOCKER_HOST", "tcp://localhost:2375") // Replace with appropriate test addr
			}
			got, err := getDockerTransport(tt.addr)
			if (err != nil) != tt.want1 {
				t.Errorf("getDockerTransport() error = %v, wantErr %v", err, tt.want1)
				return
			}
			if got == nil {
				t.Errorf("getDockerTransport() = %v, want %v", got, tt.want)
			}
			if tt.name == "Empty addr and DOCKER_HOST set" {
				os.Unsetenv("DOCKER_HOST")
			}
		})
	}
}
