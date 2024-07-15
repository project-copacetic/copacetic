package connhelpers

import (
	"testing"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
)

func TestDocker(t *testing.T) {
	_, err := connhelper.GetConnectionHelper("docker://")
	assert.NoError(t, err)
}

//type GetDockerTransport struct {
//	c         string
//	dial      string
//	host      string
//	scheme    string
//	transform string
//}

//func TestGetDockerTransport(t *testing.T) {
//	tests := []struct {
//		name        string
//		addr        string
//		want        *GetDockerTransport
//		expectError bool
//		env         string
//	}{
//		{
//			name: "Empty addr and DOCKER_HOST unset",
//			addr: "",
//			want: &GetDockerTransport{"0xc00008f260", "0x6ae860", "/var/run/docker.sock", "http", "0x6ae780"},
//		},
//		{
//			name: "Empty addr and DOCKER_HOST set",
//			addr: "",
//			want: &GetDockerTransport{"0xc00008f2f0", "0x6ae860", "/var/run/docker.sock", "http", "0x6ae780"},
//		},
//		//{
//		//	name: "docker host set to non-default value",
//		//	addr: "",
//		//	env:  "tcp://localhost:5000",
//		//	want: GetDockerTransport{"0xc00008f3b0", nil, "localhost:5000", http, nil},
//		//},
//		//{
//		//	name: "Addr set",
//		//	addr: "tcp://localhost:2375",
//		//	want: &transport.Transport{},
//		//},
//		{
//			name:        "invalid connection string",
//			addr:        "invalid_connection_string",
//			expectError: true,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if tt.env != "" {
//				os.Setenv("DOCKER_HOST", tt.env)
//				t.Cleanup(func() {
//					os.Unsetenv("DOCKER_HOST")
//				})
//			}
//
//			got, err := getDockerTransport(tt.addr)
//
//			if !assert.Equal(t, got, tt.want) {
//				t.Errorf("getDockerTransport() got = %v, want %v", got, tt.want)
//			}
//
//			if err != nil {
//				assert.ErrorContains(t, err, "protocol not supported")
//				// t.Errorf("getDockerTransport() error = %v, wantErr %v", err, tt.expectError)
//			} else {
//				assert.NoError(t, err)
//			}
//		})
//	}
//}
