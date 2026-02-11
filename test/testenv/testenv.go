// Package testenv provides a test environment for integration testing with BuildKit.
// It follows the pattern from Azure/dalec's testenv package, allowing tests to execute
// Go code directly and inspect container state via the BuildKit gateway client.
package testenv

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
)

// TestFunc is the function signature for tests that receive a gateway client.
// Tests can use the gateway client to resolve images, build LLB definitions,
// and inspect results without exporting.
type TestFunc func(ctx context.Context, t *testing.T, c gwclient.Client)

// TestEnv manages BuildKit connections for integration testing.
// It provides a way to run tests with access to a gateway client,
// enabling direct inspection of container state.
type TestEnv struct {
	addr   string
	mu     sync.Mutex
	client *client.Client
}

// New creates a new TestEnv with the given BuildKit address.
// If addr is empty, it will auto-detect the BuildKit instance
// (trying docker://, buildx, then default unix socket).
func New(addr string) *TestEnv {
	return &TestEnv{
		addr: addr,
	}
}

// ensureClient creates the BuildKit client if not already created.
func (e *TestEnv) ensureClient(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client != nil {
		return nil
	}

	bkOpts := buildkit.Opts{Addr: e.addr}
	c, err := buildkit.NewClient(ctx, bkOpts)
	if err != nil {
		return fmt.Errorf("failed to create buildkit client: %w", err)
	}

	if err := buildkit.ValidateClient(ctx, c); err != nil {
		c.Close()
		return fmt.Errorf("buildkit client validation failed: %w", err)
	}

	e.client = c
	return nil
}

// Client returns the underlying BuildKit client, creating it if necessary.
// This can be useful for tests that need direct access to the client.
func (e *TestEnv) Client(ctx context.Context) (*client.Client, error) {
	if err := e.ensureClient(ctx); err != nil {
		return nil, err
	}
	return e.client, nil
}

// RunTest executes a test function with a gateway client.
// The gateway client is obtained via client.Build() callback, which provides
// the context needed for LLB operations and result inspection.
//
// Example usage:
//
//	env := testenv.New(os.Getenv("COPA_BUILDKIT_ADDR"))
//	defer env.Close()
//
//	env.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
//	    // Use gateway client to resolve images, build, inspect results
//	    _, _, cfg, err := c.ResolveImageConfig(ctx, "alpine:latest", sourceresolver.Opt{})
//	    require.NoError(t, err)
//	    // ... assertions
//	})
func (e *TestEnv) RunTest(ctx context.Context, t *testing.T, f TestFunc, opts ...TestRunnerOpt) {
	t.Helper()

	cfg := &TestRunnerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if err := e.ensureClient(ctx); err != nil {
		t.Fatalf("failed to ensure buildkit client: %v", err)
	}

	solveOpt := cfg.SolveOpts
	if cfg.SkipExport {
		solveOpt.Exports = nil
	}

	var testErr error
	_, err := e.client.Build(ctx, solveOpt, "copa-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		// Capture any test failures via panic recovery
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok {
					testErr = err
				} else {
					testErr = fmt.Errorf("test panic: %v", r)
				}
			}
		}()

		f(ctx, t, c)
		return &gwclient.Result{}, nil
	}, nil)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if testErr != nil {
		t.Fatalf("test failed: %v", testErr)
	}
}

// Close closes the BuildKit client connection.
// It should be called when the test environment is no longer needed.
func (e *TestEnv) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client != nil {
		err := e.client.Close()
		e.client = nil
		return err
	}
	return nil
}

// Addr returns the BuildKit address used by this test environment.
func (e *TestEnv) Addr() string {
	return e.addr
}

// NormalizeImageRef normalizes an image reference to its fully qualified form.
// This is necessary because BuildKit's gateway client requires fully qualified
// image references (e.g., "docker.io/library/alpine:latest" instead of "alpine:latest")
// to properly parse the URL when resolving image configs.
//
// Examples:
//
//	NormalizeImageRef("alpine:latest") returns "docker.io/library/alpine:latest"
//	NormalizeImageRef("nginx:1.21") returns "docker.io/library/nginx:1.21"
//	NormalizeImageRef("ghcr.io/myorg/myimage:v1") returns "ghcr.io/myorg/myimage:v1"
func NormalizeImageRef(imageRef string) string {
	named, err := reference.ParseNormalizedNamed(imageRef)
	if err != nil {
		// If parsing fails, return the original reference
		return imageRef
	}
	// Add default tag if missing
	named = reference.TagNameOnly(named)
	return named.String()
}
