package connhelpers

import (
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
	"sync"

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

var (
	buildxExecCommand        = exec.Command
	buildxExecCommandContext = exec.CommandContext
)

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
	cmd := buildxExecCommandContext(ctx, "docker", "buildx", "dial-stdio", "--help")
	return cmd.Run() == nil
}

type buildxProxyWriter struct {
	io.Writer
	once  sync.Once
	ready chan struct{}
}

func (w *buildxProxyWriter) Write(p []byte) (int, error) {
	if len(p) != 0 {
		w.once.Do(func() { close(w.ready) })
	}
	return w.Writer.Write(p)
}

type buildxProgressWriter struct {
	mu      sync.Mutex
	output  bytes.Buffer
	pending string
	errors  chan string
}

func (w *buildxProgressWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, _ = w.output.Write(p)
	w.pending += string(p)
	for {
		end := strings.IndexByte(w.pending, '\n')
		if end == -1 {
			break
		}

		line := strings.TrimSuffix(w.pending[:end], "\r")
		w.pending = w.pending[end+1:]
		if strings.Contains(strings.ToLower(line), "error:") {
			select {
			case w.errors <- line:
			default:
			}
		}
	}
	return len(p), nil
}

func (w *buildxProgressWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.String()
}

// buildxDialStdio uses the buildx dial-stdio command to connect to a buildx instance.
//
// The way this works is it uses the buildx CLI as a proxy to connect to the buildx instance.
// The connection is proxied over the stdin/stdout of the buildx CLI.
//
// This allows us to support any buildx instance, even if it is not running in a container.
func buildxDialStdio(ctx context.Context, builder string) (net.Conn, error) {
	cmd := buildxExecCommand("docker", "buildx", "dial-stdio", "--progress=plain")
	if builder != "" {
		cmd.Args = append(cmd.Args, "--builder", builder)
	}
	cmd.Env = buildxDialStdioEnv(builder)

	c1, c2 := net.Pipe()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		c1.Close()
		c2.Close()
		return nil, fmt.Errorf("create buildx dial-stdio stdin pipe: %w", err)
	}
	proxyReady := make(chan struct{})
	cmd.Stdout = &buildxProxyWriter{Writer: c1, ready: proxyReady}
	progressErrors := make(chan string, 1)
	progress := &buildxProgressWriter{errors: progressErrors}
	cmd.Stderr = progress

	if err := cmd.Start(); err != nil {
		stdin.Close()
		c1.Close()
		c2.Close()
		return nil, err
	}

	var closeProxyOnce sync.Once
	closeProxy := func() {
		closeProxyOnce.Do(func() {
			stdin.Close()
			c1.Close()
			c2.Close()
			_ = cmd.Process.Kill()
		})
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		// Close both ends of the proxy and stop the process so cancellation
		// cannot leave any proxy copy blocked before the connection is ready.
		closeProxy()
	})
	defer stopCancellation()

	go func() {
		// Keep the stdin copy outside os/exec so cmd.Wait can report an early
		// process exit even while no client data has arrived on the proxy.
		_, _ = io.Copy(stdin, c1)
		_ = stdin.Close()
	}()

	processDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		c1.Close()
		if err == nil {
			err = errors.New("buildx dial-stdio exited before connecting")
		} else if detail := strings.TrimSpace(progress.String()); detail != "" {
			err = fmt.Errorf("%w: %s", err, detail)
		}
		processDone <- err
	}()

	for {
		select {
		case <-proxyReady:
			// Buildx reports the Dialing builder sub-progress as done even when
			// build.Dial returns an error. The first proxy output is the point at
			// which Buildx has actually connected and started forwarding bytes.
			select {
			case line := <-progressErrors:
				closeProxy()
				return nil, fmt.Errorf("buildx dial-stdio failed before connecting: %s", line)
			case err := <-processDone:
				closeProxy()
				return nil, fmt.Errorf("buildx dial-stdio failed before connecting: %w", err)
			default:
			}
			if !stopCancellation() {
				closeProxy()
				return nil, ctx.Err()
			}
			return c2, nil
		case line := <-progressErrors:
			closeProxy()
			return nil, fmt.Errorf("buildx dial-stdio failed before connecting: %s", line)
		case err := <-processDone:
			closeProxy()
			return nil, fmt.Errorf("buildx dial-stdio failed before connecting: %w", err)
		case <-ctx.Done():
			closeProxy()
			return nil, ctx.Err()
		}
	}
}

// buildxDialStdioEnv prevents a Docker endpoint override that is needed by a
// later image loader from changing the context used by an explicitly selected
// Buildx builder. Context-bound docker driver builders otherwise reject the
// connection before the gRPC client can start, leaving it waiting until the
// patch timeout. An unnamed builder continues to honor DOCKER_HOST.
func buildxDialStdioEnv(builder string) []string {
	env := os.Environ()
	if builder == "" {
		return env
	}

	filtered := env[:0]
	for _, entry := range env {
		if strings.HasPrefix(entry, "DOCKER_HOST=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
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
