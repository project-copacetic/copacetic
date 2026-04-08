package imageloader

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	dockerClient "github.com/moby/moby/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit/connhelpers"
	log "github.com/sirupsen/logrus"
)

// dockerAPIClient defines the interface for Docker client operations needed by dockerLoader.
// This allows for easier mocking in tests.
type dockerAPIClient interface {
	Ping(ctx context.Context, options dockerClient.PingOptions) (dockerClient.PingResult, error)
	ImageLoad(ctx context.Context, input io.Reader, loadOpts ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error)
}

type dockerLoader struct{ cli dockerAPIClient }

func probeDocker(ctx context.Context) (Loader, bool) {
	opts := []dockerClient.Opt{
		dockerClient.FromEnv,
		dockerClient.WithAPIVersionNegotiation(),
	}

	// If DOCKER_HOST is not set, try to resolve from docker context
	if os.Getenv(dockerClient.EnvOverrideHost) == "" {
		addr, err := connhelpers.AddrFromDockerContext()
		if err != nil {
			log.WithError(err).Error("Error loading docker context, falling back to env")
		} else if addr != "" {
			opts = append(opts, dockerClient.WithHost(addr))
		}
	}

	cli, err := dockerClient.NewClientWithOpts(opts...)
	if err != nil {
		return nil, false
	}
	if _, err = cli.Ping(ctx, dockerClient.PingOptions{}); err != nil {
		return nil, false
	}
	return &dockerLoader{cli: cli}, true
}

// Load streams the tarball into either Docker or Podman.
func (d *dockerLoader) Load(ctx context.Context, tar io.Reader, _ string) error {
	log.Debug("Loading image stream using Docker API client")
	resp, err := d.cli.ImageLoad(ctx, tar, dockerClient.ImageLoadWithQuiet(false))
	if err != nil {
		return fmt.Errorf("docker ImageLoad: %w", err)
	}
	defer resp.Close()

	scanner := bufio.NewScanner(resp)
	lastLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		lastLine = line
		log.Debugf("ImageLoad response stream: %s", line)
	}
	if err := scanner.Err(); err != nil {
		log.Warnf("error reading ImageLoad response: %v", err)
	}

	if lastLine != "" {
		var jsonResp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(lastLine), &jsonResp); err == nil && jsonResp.Error != "" {
			return fmt.Errorf("ImageLoad error: %s", jsonResp.Error)
		}
	}

	log.Debug("image loaded successfully via Docker API")
	return nil
}
