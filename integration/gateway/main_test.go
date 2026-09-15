// Package gateway provides integration tests that use the BuildKit gateway client
// directly, following the pattern from Azure/dalec's testenv package.
//
// These tests execute Go code directly rather than invoking the copa CLI binary,
// enabling faster tests and direct inspection of container state before export.
package gateway

import (
	"flag"
	"os"
	"testing"

	// Register connection helpers for buildkit (required for podman-container://, docker-container://, etc.)
	_ "github.com/moby/buildkit/client/connhelper/dockercontainer"
	_ "github.com/moby/buildkit/client/connhelper/podmancontainer"

	"github.com/project-copacetic/copacetic/test/testenv"
)

var (
	// testEnv is the shared test environment for all tests in this package.
	testEnv *testenv.TestEnv

	// buildkitAddr is the BuildKit address to use for tests.
	// Can be set via -addr flag or COPA_BUILDKIT_ADDR environment variable.
	buildkitAddr string
)

func TestMain(m *testing.M) {
	flag.StringVar(&buildkitAddr, "addr", "", "BuildKit address (e.g., docker://, tcp://localhost:1234)")
	flag.Parse()

	// If no address provided via flag, check environment variable
	if buildkitAddr == "" {
		buildkitAddr = os.Getenv("COPA_BUILDKIT_ADDR")
	}

	// Create test environment
	testEnv = testenv.New(buildkitAddr)

	// Run tests
	code := m.Run()

	// Cleanup
	testEnv.Close()

	os.Exit(code)
}
