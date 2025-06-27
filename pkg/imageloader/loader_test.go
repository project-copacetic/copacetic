package imageloader

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestNew_DockerUnavailable(t *testing.T) {
	ctx := context.Background()

	oldHost := os.Getenv("DOCKER_HOST")
	t.Cleanup(func() { _ = os.Setenv("DOCKER_HOST", oldHost) })
	_ = os.Setenv("DOCKER_HOST", "unix:///definitely/not/there.sock")

	_, err := New(ctx, Config{Loader: Docker})
	if err == nil || !strings.Contains(err.Error(), "docker socket not reachable") {
		t.Fatalf("expected docker socket not reachable error, got %v", err)
	}
}

func TestNew_PodmanUnavailable(t *testing.T) {
	ctx := context.Background()

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	_ = os.Setenv("PATH", "")

	_, err := New(ctx, Config{Loader: Podman})
	if err == nil || !strings.Contains(err.Error(), "podman socket not reachable") {
		t.Fatalf("expected podman socket not reachable error, got %v", err)
	}
}

func TestNew_DefaultSelectFallback_HappyPath(t *testing.T) {
	ctx := context.Background()

	// this test checks if New() successfully finds *any* available loader
	// when Select is empty. It skips if neither is available, which is
	// pragmatic for CI environments that might not have any runtime.
	if _, err := New(ctx, Config{}); err != nil {
		// environment doesnt have Docker or Podman—acceptable for CI, so skip.
		t.Skipf("no container runtime detected on this host: %v", err)
	}
}

func TestNew_UnknownLoader(t *testing.T) {
	ctx := context.Background()
	_, err := New(ctx, Config{Loader: "nonExistentLoader"})
	if err == nil {
		t.Fatal("expected an error for unknown loader, got nil")
	}
	expectedErrorMsg := "unknown loader \"nonExistentLoader\""
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Fatalf("expected error message '%s', got: %v", expectedErrorMsg, err)
	}
}

func TestNew_DockerFails_PodmanSucceeds_ImplicitSelect(t *testing.T) {
	ctx := context.Background()

	// mock Docker to be unavailable
	oldDockerHost := os.Getenv("DOCKER_HOST")
	_ = os.Setenv("DOCKER_HOST", "unix:///definitely/not/there.sock")
	defer func() { _ = os.Setenv("DOCKER_HOST", oldDockerHost) }()

	// ensure Podman is available (using the fake one)
	cleanupPodman := makeFakePodman(t, 0)
	defer cleanupPodman()

	loader, err := New(ctx, Config{Loader: ""})
	if err != nil {
		t.Fatalf("New() failed when Podman should have been selected: %v", err)
	}
	if loader == nil {
		t.Fatal("expected a podman loader, got nil")
	}
	if _, ok := loader.(*podmanLoader); !ok {
		t.Fatalf("expected a *podmanLoader, got %T", loader)
	}
}
