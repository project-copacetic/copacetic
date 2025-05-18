package connhelpers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

func supportsDialStio(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "buildx", "dial-stdio", "--help")
	return cmd.Run() == nil
}

// buildxDialStdio uses the buildx dial-stdio command to connect to a buildx instance.
//
// The way this works is it uses the buildx CLI as a proxy to connect to the buildx instance.
// The connection is proxied over the stdin/stdout of the buildx CLI.
//
// This allows us to support any buildx instance, even if it is not running in a container.
func buildxDialStdio(ctx context.Context, builder string) (net.Conn, error) {
	cmd := exec.CommandContext(ctx, "docker", "buildx", "dial-stdio", "--progress=plain")
	if builder != "" {
		cmd.Args = append(cmd.Args, "--builder", builder)
	}
	cmd.Env = os.Environ()

	c1, c2 := net.Pipe()
	cmd.Stdin = c1
	cmd.Stdout = c1

	// Use a pipe to check when the connection is actually complete
	// Also write all of stderr to an error buffer so we can have more details
	// in the error message when the command fails.
	r, w := io.Pipe()
	errBuf := bytes.NewBuffer(nil)
	ww := io.MultiWriter(w, errBuf)
	cmd.Stderr = ww

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		err := cmd.Wait()
		c1.Close()
		// pkgerrors.Wrap will return nil if err is nil, otherwise it will give
		// us a wrapped error with the buffered stderr from he command.
		w.CloseWithError(fmt.Errorf("%s: %s", err, errBuf))
	}()

	defer r.Close()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		txt := strings.ToLower(scanner.Text())

		if strings.HasPrefix(txt, "#1 dialing builder") && strings.HasSuffix(txt, "done") {
			go func() {
				// Continue draining stderr so the process does not get blocked
				_, _ = io.Copy(io.Discard, r)
			}()
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return c2, nil
}

func buildxContextDialer(builder string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		if supportsDialStio(ctx) {
			return buildxDialStdio(ctx, builder)
		}

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
