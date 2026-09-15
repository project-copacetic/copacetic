package connhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/cpuguy83/go-docker/transport"
	"github.com/cpuguy83/go-docker/version"
	"github.com/moby/buildkit/client/connhelper"
	log "github.com/sirupsen/logrus"
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
		var err error
		addr, err = AddrFromDockerContext()
		if err != nil {
			if errors.Is(err, errNoDockerContext) {
				return transport.DefaultTransport()
			}
			return nil, fmt.Errorf("error getting docker context: %w", err)
		}
	}

	if !strings.Contains(addr, ":/") {
		// This is probably a docker context name
		var err error
		addr, err = addrFromContext(addr)
		if err != nil {
			log.WithError(err).WithField("docker context", addr).Debug("Error getting docker context, assuming connection string")
		}
	}
	return transport.FromConnectionString(addr)
}

var errNoDockerContext = fmt.Errorf("no docker context found")

func addrFromContext(name string) (string, error) {
	cmd := exec.Command("docker", "context", "inspect", name, "--format", "{{.Endpoints.docker.Host}}")

	out, err := cmd.CombinedOutput()
	if err != nil {
		out := string(out)
		return "", fmt.Errorf("error inspecting docker context %q: %w: %s", name, err, out)
	}

	addr := strings.TrimSpace(string(out))
	return addr, nil
}

func AddrFromDockerContext() (_ string, retErr error) {
	if v := os.Getenv("DOCKER_CONTEXT"); v != "" {
		// context is defiend in the env, no need to scan for it
		return addrFromContext(v)
	}

	cmd := exec.Command("docker", "context", "ls", "--format", "json")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("error creating stdout pipe: %w", err)
	}
	defer stdout.Close()

	stderr := bytes.NewBuffer((nil))
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("error starting docker context ls: %w", err)
	}

	defer func() {
		err := cmd.Wait()
		if retErr == nil {
			retErr = err
			return
		}
		retErr = fmt.Errorf("%w: %w: %s", err, retErr, stderr)
	}()

	type contextEntry struct {
		Endpoint string `json:"DockerEndpoint"`
		Current  bool   `json:"Current"`
	}

	var entry contextEntry

	dec := json.NewDecoder(stdout)
	for {
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				return "", errNoDockerContext
			}
			return "", fmt.Errorf("error decoding docker context ls output: %w", err)
		}

		if entry.Current {
			return entry.Endpoint, nil
		}
	}
}
