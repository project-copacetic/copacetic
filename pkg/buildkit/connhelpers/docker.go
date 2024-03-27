package connhelpers

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/cpuguy83/go-docker/transport"
	"github.com/cpuguy83/go-docker/version"
	"github.com/moby/buildkit/client/connhelper"
)

func init() {
	connhelper.Register("docker", Docker)
}

// Docker returns a buildkit connection helper for connecting to a docker daemon.
func Docker(u *url.URL) (*connhelper.ConnectionHelper, error) {
	return &connhelper.ConnectionHelper{
		ContextDialer: func(ctx context.Context, _ string) (net.Conn, error) {
			tr, err := getDockerTransport(path.Join(u.Host, u.Path))
			if err != nil {
				return nil, err
			}
			return tr.DoRaw(ctx, http.MethodPost, version.Join(ctx, "/grpc"), transport.WithUpgrade("h2c"))
		},
	}, nil
}

func getDockerTransport(addr string) (transport.Doer, error) {
	if addr == "" {
		addr = os.Getenv("DOCKER_HOST")
	}
	if addr == "" {
		return transport.DefaultTransport()
	}
	return transport.FromConnectionString(addr)
}
