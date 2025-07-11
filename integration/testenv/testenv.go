package testenv

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type Env struct {
	Ctx      context.Context
	Buildkit *BuildkitdContainer
	Registry *RegistryContainer
}

type BuildkitdContainer struct {
	Container testcontainers.Container
	Address   string
	Client    *client.Client
	Gateway   gwclient.Client
}

type RegistryContainer struct {
	Container testcontainers.Container
	Address   string
}

func New(t *testing.T) *Env {
	ctx := context.Background()

	buildkitd, err := newBuildkitd(ctx)
	if err != nil {
		t.Fatalf("Failed to start buildkitd: %v", err)
	}

	registry, err := newRegistry(ctx)
	if err != nil {
		buildkitd.Container.Terminate(ctx)
		t.Fatalf("Failed to start registry: %v", err)
	}

	return &Env{
		Ctx:      ctx,
		Buildkit: buildkitd,
		Registry: registry,
	}
}

func (e *Env) Teardown() {
	if e.Buildkit != nil && e.Buildkit.Client != nil {
		e.Buildkit.Client.Close()
	}
	if e.Buildkit != nil && e.Buildkit.Container != nil {
		e.Buildkit.Container.Terminate(e.Ctx)
	}
	if e.Registry != nil && e.Registry.Container != nil {
		e.Registry.Container.Terminate(e.Ctx)
	}
}

func newBuildkitd(ctx context.Context) (*BuildkitdContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      "moby/buildkit:v0.12.5",
		Privileged: true,
		WaitingFor: wait.ForLog("buildkitd is running").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("docker://%s", container.GetContainerID())

	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create buildkit client: %w", err)
	}

	return &BuildkitdContainer{
		Container: container,
		Address:   addr,
		Client:    c,
	}, nil
}

func newRegistry(ctx context.Context) (*RegistryContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForListeningPort("5000/tcp"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	endpoint, err := container.Endpoint(ctx, "")
	if err != nil {
		return nil, err
	}

	return &RegistryContainer{
		Container: container,
		Address:   endpoint,
	}, nil
}
