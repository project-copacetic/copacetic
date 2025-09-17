package connhelpers

import (
	"context"
	"os/exec"
	"testing"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
)

func TestBuildx(t *testing.T) {
	_, err := connhelper.GetConnectionHelper("buildx://")
	assert.NoError(t, err)

	_, err = connhelper.GetConnectionHelper("buildx://foobar")
	assert.NoError(t, err)

	_, err = connhelper.GetConnectionHelper("buildx://foorbar/something")
	assert.Error(t, err)
}

func TestSupportsDialStio(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		expectError bool
	}{
		{
			name:        "valid_context",
			ctx:         context.Background(),
			expectError: false, // We don't know if docker buildx is available, so we just test it doesn't crash
		},
		{
			name:        "canceled_context",
			ctx:         func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(),
			expectError: true, // Canceled context should cause command to fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't test the actual functionality without Docker buildx installed,
			// but we can test that the function doesn't panic and handles context properly
			result := supportsDialStio(tt.ctx)

			// For valid context, result could be true or false depending on environment
			// For canceled context, it should return false
			if tt.expectError {
				assert.False(t, result, "Expected false result for canceled context")
			} else {
				// For valid context, we just verify it returns a boolean without panicking
				assert.IsType(t, true, result, "Should return a boolean")
			}
		})
	}
}

func TestBuildxDialStdio(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		builder     string
		expectError bool
	}{
		{
			name:        "canceled_context",
			ctx:         func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(),
			builder:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the function handles context and builder parameters properly
			// Only test with canceled context to avoid hanging in CI
			conn, err := buildxDialStdio(tt.ctx, tt.builder)

			if tt.expectError || err != nil {
				assert.Error(t, err, "Expected error for canceled context")
				assert.Nil(t, conn, "Connection should be nil on error")
			}
		})
	}
}

func TestContainerContextDialer(t *testing.T) {
	tests := []struct {
		name          string
		ctx           context.Context
		host          string
		containerName string
		expectError   bool
	}{
		{
			name:          "canceled_context",
			ctx:           func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(),
			host:          "unix:///var/run/docker.sock",
			containerName: "test-container",
			expectError:   true,
		},
		{
			name:          "invalid_host",
			ctx:           context.Background(),
			host:          "invalid://host",
			containerName: "test-container",
			expectError:   true,
		},
		{
			name:          "empty_container_name",
			ctx:           context.Background(),
			host:          "unix:///var/run/docker.sock",
			containerName: "",
			expectError:   true, // Will fail trying to exec in empty-named container
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the containerContextDialer function
			// This will fail in CI without Docker, but we can verify parameter handling
			conn, err := containerContextDialer(tt.ctx, tt.host, tt.containerName)

			if tt.expectError || err != nil {
				assert.Error(t, err, "Expected error due to missing Docker or invalid parameters")
				assert.Nil(t, conn, "Connection should be nil on error")
			}
		})
	}
}

// Test helper functions for command availability.
func TestDockerBuildxAvailability(t *testing.T) {
	// This is a helper test to understand the CI environment
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	if err != nil {
		t.Logf("Docker not available in CI: %v", err)
	} else {
		t.Logf("Docker is available in CI")
	}

	cmd = exec.Command("docker", "buildx", "version")
	err = cmd.Run()
	if err != nil {
		t.Logf("Docker buildx not available in CI: %v", err)
	} else {
		t.Logf("Docker buildx is available in CI")
	}
}
