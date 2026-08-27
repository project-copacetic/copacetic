package connhelpers

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestBuildxDialStdioIgnoresDockerHostForNamedBuilder(t *testing.T) {
	originalCommand := buildxExecCommand
	t.Cleanup(func() { buildxExecCommand = originalCommand })
	buildxExecCommand = buildxDialHelperCommand

	t.Setenv("DOCKER_HOST", "unix:///docker-loader.sock")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)

	conn, err := buildxDialStdio(ctx, "desktop-linux")
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())
}

func TestBuildxDialStdioReturnsEarlyProgressError(t *testing.T) {
	originalCommand := buildxExecCommand
	t.Cleanup(func() { buildxExecCommand = originalCommand })
	buildxExecCommand = buildxDialHelperCommand

	t.Setenv("BUILDX_DIAL_HELPER_FAIL", "1")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)

	conn, err := buildxDialStdio(ctx, "desktop-linux")
	require.ErrorContains(t, err, "buildx dial-stdio failed before connecting")
	assert.Nil(t, conn)
}

func TestBuildxDialStdioReturnsErrorAfterDialProgressCompletes(t *testing.T) {
	originalCommand := buildxExecCommand
	t.Cleanup(func() { buildxExecCommand = originalCommand })
	buildxExecCommand = buildxDialHelperCommand

	t.Setenv("BUILDX_DIAL_HELPER_LATE_FAIL", "1")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)

	conn, err := buildxDialStdio(ctx, "desktop-linux")
	require.ErrorContains(t, err, "buildx dial-stdio failed before connecting")
	assert.Nil(t, conn)
}

func TestBuildxDialStdioCancellationClosesProxy(t *testing.T) {
	originalCommand := buildxExecCommand
	t.Cleanup(func() { buildxExecCommand = originalCommand })
	buildxExecCommand = buildxDialHelperCommand

	t.Setenv("BUILDX_DIAL_HELPER_SILENT", "1")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	t.Cleanup(cancel)

	conn, err := buildxDialStdio(ctx, "desktop-linux")
	require.Error(t, err)
	assert.Nil(t, conn)
}

func TestBuildxDialStdioKeepsProxyOpenAfterDialContextEnds(t *testing.T) {
	originalCommand := buildxExecCommand
	t.Cleanup(func() { buildxExecCommand = originalCommand })
	buildxExecCommand = buildxDialHelperCommand

	ctx, cancel := context.WithCancel(t.Context())
	conn, err := buildxDialStdio(ctx, "desktop-linux")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	ready := make([]byte, len("proxy ready"))
	_, err = io.ReadFull(conn, ready)
	require.NoError(t, err)
	assert.Equal(t, "proxy ready", string(ready))

	cancel()
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte("connection remains open"))
	require.NoError(t, err)
}

func buildxDialHelperCommand(_ string, _ ...string) *exec.Cmd {
	//nolint:gosec // os.Args[0] is the Go test binary, not untrusted input.
	return exec.Command(os.Args[0], "-test.run=^TestBuildxDialStdioHelperProcess$", "--", "--buildx-dial-helper")
}

func TestBuildxDialStdioHelperProcess(t *testing.T) {
	if !slices.Contains(os.Args, "--buildx-dial-helper") {
		return
	}

	if os.Getenv("DOCKER_HOST") != "" || os.Getenv("BUILDX_DIAL_HELPER_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "ERROR: use the builder's Docker context")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(1)
	}
	if os.Getenv("BUILDX_DIAL_HELPER_SILENT") != "" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}

	// The progress vertex number is deliberately not #1. It is presentation
	// detail and must not be part of the connection readiness contract.
	fmt.Fprintln(os.Stderr, "#7 Dialing builder 0.0s done")
	if os.Getenv("BUILDX_DIAL_HELPER_LATE_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "#1 ERROR: failed to dial builder: context deadline exceeded")
		os.Exit(1)
	}
	fmt.Fprint(os.Stdout, "proxy ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestBuildxDialStdioEnvPreservesDockerHostForUnnamedBuilder(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://builder.example:2375")

	assert.Contains(t, buildxDialStdioEnv(""), "DOCKER_HOST=tcp://builder.example:2375")
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
