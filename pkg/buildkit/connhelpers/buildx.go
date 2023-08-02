package connhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cpuguy83/dockercfg"
	"github.com/cpuguy83/go-docker"
	"github.com/cpuguy83/go-docker/container"
	"github.com/cpuguy83/go-docker/errdefs"
	"github.com/moby/buildkit/client/connhelper"
	log "github.com/sirupsen/logrus"
)

func init() {
	connhelper.Register("buildx", Buildx)
}

type buildxConfig struct {
	Driver string
	Nodes  []struct {
		Name     string
		Endpoint string
	}
}

// Buildx returns a buildkit connection helper for connecting to a buildx instance.
// Only "docker-container" buildkit instances are currently supported.
// If there are multiple nodes configured, one will be chosen at random.
func Buildx(u *url.URL) (*connhelper.ConnectionHelper, error) {
	if u.Path != "" {
		return nil, fmt.Errorf("buildx driver does not support path elements: %s", u.Path)
	}
	return &connhelper.ConnectionHelper{
		ContextDialer: buildxContextDialer(u.Host),
	}, nil
}

func buildxContextDialer(builder string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		configPath, err := dockercfg.ConfigPath()
		if err != nil {
			return nil, err
		}

		if builder == "" {
			// Standard env for setting a buildx builder name to use
			// This is used by buildx so we should use it too.
			builder = os.Getenv("BUILDX_BUILDER")
		}

		base := filepath.Join(filepath.Dir(configPath), "buildx")
		if builder == "" {
			dt, err := os.ReadFile(filepath.Join(base, "current"))
			if err != nil {
				return nil, err
			}
			type ref struct {
				Name string `json:"name"`
			}
			var r ref
			if err := json.Unmarshal(dt, &r); err != nil {
				return nil, fmt.Errorf("could not unmarshal buildx config: %w", err)
			}
			builder = r.Name
		}

		// Note: buildx inspect does not return json here, so we can't use the output directly
		cmd := exec.CommandContext(ctx, "docker", "buildx", "inspect", "--bootstrap", builder)
		errBuf := bytes.NewBuffer(nil)
		cmd.Stderr = errBuf
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("could not inspect buildx instance: %w: %s", err, errBuf.String())
		}

		// Read the config from the buildx instance
		dt, err := os.ReadFile(filepath.Join(base, "instances", builder))
		if err != nil {
			return nil, err
		}

		var cfg buildxConfig
		if err := json.Unmarshal(dt, &cfg); err != nil {
			return nil, fmt.Errorf("could not unmarshal buildx instance config: %w", err)
		}

		if cfg.Driver != "docker-container" {
			return nil, fmt.Errorf("unsupported buildx driver: %s", cfg.Driver)
		}

		if len(cfg.Nodes) == 0 {
			return nil, errors.New("no nodes configured for buildx instance")
		}

		log.WithFields(log.Fields{
			"driver":   cfg.Driver,
			"endpoint": cfg.Nodes[0].Endpoint,
			"name":     cfg.Nodes[0].Name,
		}).Debug("Connect to buildx instance")

		nodes := cfg.Nodes
		if len(nodes) > 1 {
			rand.Shuffle(len(nodes), func(i, j int) {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			})
		}
		return containerContextDialer(ctx, nodes[0].Endpoint, "buildx_buildkit_"+nodes[0].Name)
	}
}

func containerContextDialer(ctx context.Context, host, name string) (net.Conn, error) {
	tr, err := getDockerTransport(host)
	if err != nil {
		return nil, err
	}

	cli := docker.NewClient(docker.WithTransport(tr))
	c := cli.ContainerService().NewContainer(ctx, name)

	conn1, conn2 := net.Pipe()
	ep, err := c.Exec(ctx, container.WithExecCmd("buildctl", "dial-stdio"), func(cfg *container.ExecConfig) {
		cfg.Stdin = conn1
		cfg.Stdout = conn1
		cfg.Stderr = conn1
	})
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("could not find container %s: %w", name, err)
		}
		if err2 := c.Start(ctx); err2 != nil {
			return nil, err
		}

		ep, err = c.Exec(ctx, container.WithExecCmd("buildctl", "dial-stdio"), func(cfg *container.ExecConfig) {
			cfg.Stdin = conn1
			cfg.Stdout = conn1
			cfg.Stderr = conn1
		})
		if err != nil {
			return nil, err
		}
	}

	if err := ep.Start(ctx); err != nil {
		return nil, fmt.Errorf("could not start exec proxy: %w", err)
	}

	return conn2, nil
}
