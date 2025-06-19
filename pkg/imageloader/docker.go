package imageloader

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	dockerClient "github.com/docker/docker/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit/connhelpers"
	log "github.com/sirupsen/logrus"
)

// dockerAPIClient defines the interface for Docker client operations needed by dockerLoader.
// This allows for easier mocking in tests.
type dockerAPIClient interface {
	Ping(ctx context.Context) (dockerTypes.Ping, error)
	ImageLoad(ctx context.Context, input io.Reader, loadOpts ...dockerClient.ImageLoadOption) (image.LoadResponse, error)
}

type dockerLoader struct{ cli dockerAPIClient }

func probeDocker(ctx context.Context) (Loader, bool) {
	hostOpt := func(c *dockerClient.Client) error {
		if os.Getenv(dockerClient.EnvOverrideHost) != "" {
			// Fallback to just keep dockerClient.FromEnv whatever was set from
			return nil
		}
		addr, err := connhelpers.AddrFromDockerContext()
		if err != nil {
			log.WithError(err).Error("Error loading docker context, falling back to env")
			return nil
		}
		return dockerClient.WithHost(addr)(c)
	}
	cli, err := dockerClient.NewClientWithOpts(
		dockerClient.FromEnv,
		hostOpt,
		dockerClient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, false
	}
	if _, err = cli.Ping(ctx); err != nil {
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
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	lastLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		lastLine = line
		log.Debugf("ImageLoad response stream: %s", line)
	}
	if err := scanner.Err(); err != nil {
		log.Warnf("error reading ImageLoad response: %v", err)
	}

	if resp.JSON && lastLine != "" {
		var jsonResp struct {
			ErrorResponse *dockerTypes.ErrorResponse `json:"errorResponse"`
			Error         string                     `json:"error"`
		}
		if err := json.Unmarshal([]byte(lastLine), &jsonResp); err == nil {
			switch {
			case jsonResp.ErrorResponse != nil:
				return fmt.Errorf("ImageLoad error: %s", jsonResp.ErrorResponse.Message)
			case jsonResp.Error != "":
				return fmt.Errorf("ImageLoad error: %s", jsonResp.Error)
			}
		} else {
			log.Debugf("final ImageLoad line (non-JSON): %s", lastLine)
		}
	} else if lastLine != "" {
		log.Debugf("final ImageLoad line (non-JSON): %s", lastLine)
	}

	log.Info("image loaded successfully via Docker API")
	return nil
}
