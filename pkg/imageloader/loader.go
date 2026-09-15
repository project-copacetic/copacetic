package imageloader

import (
	"context"
	"fmt"
	"io"
)

// Loader type constants.
const (
	Docker = "docker"
	Podman = "podman"
)

// Loader streams an OCI/Docker tar archive into a local container engine.
type Loader interface {
	Load(ctx context.Context, tar io.Reader, imageRef string) error
}

// Config is the configuration for the image loader.
// It specifies which container engine to use for loading images.
type Config struct {
	// Docker | Podman | ""
	Loader string
}

// New instantiates the concrete loader.
func New(ctx context.Context, cfg Config) (Loader, error) {
	switch cfg.Loader {
	case Docker, "":
		if l, ok := probeDocker(ctx); ok {
			return l, nil
		}
		if cfg.Loader == Docker {
			return nil, fmt.Errorf("docker socket not reachable")
		}
		fallthrough
	case Podman:
		if l, ok := probePodman(ctx); ok {
			return l, nil
		}
		if cfg.Loader == Podman {
			return nil, fmt.Errorf("podman socket not reachable")
		}
		fallthrough
	default:
		return nil, fmt.Errorf("unknown loader %q", cfg.Loader)
	}
}
