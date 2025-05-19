package imageloader

import (
	"context"
	"fmt"
	"io"
)

// Loader streams an OCI/Docker tar archive into a local container engine.
type Loader interface {
	Load(ctx context.Context, tar io.Reader, imageRef string) error
}

// Config is the configuration for the image loader.
// It specifies which container engine to use for loading images.
type Config struct {
	// "docker" | "podman" | ""
	Loader string
}

// New instantiates the concrete loader.
func New(ctx context.Context, cfg Config) (Loader, error) {
	switch cfg.Loader {
	case "docker", "":
		if l, ok := probeDocker(ctx); ok {
			return l, nil
		}
		if cfg.Loader == "docker" {
			return nil, fmt.Errorf("docker socket not reachable")
		}
		fallthrough
	case "podman":
		if l, ok := probePodman(ctx); ok {
			return l, nil
		}
		if cfg.Loader == "podman" {
			return nil, fmt.Errorf("podman socket not reachable")
		}
		fallthrough
	default:
		return nil, fmt.Errorf("unknown loader %q", cfg.Loader)
	}
}
