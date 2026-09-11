//go:build integration

package pkgmgr

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	bkclient "github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// Run with COPA_BUILDKIT_ADDR=docker:// go test -tags=integration ./pkg/pkgmgr
// -run TestUpdateChecksWithBuildKit. Controlled executables isolate the shell
// and BuildKit error boundary from live repository availability.
func TestUpdateChecksWithBuildKit(t *testing.T) {
	addr := os.Getenv("COPA_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("COPA_BUILDKIT_ADDR is required for BuildKit integration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	_, err = client.Build(ctx, bkclient.SolveOpt{}, "copa-update-check-test", func(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
		const tool = "/usr/local/bin/copa-check-test-tool"
		base := llb.Image("docker.io/library/alpine:3.20", llb.ResolveModePreferLocal).
			Network(llb.NetModeNone).
			File(llb.Mkfile(tool, 0o755, []byte(updateCheckTestTool))).
			File(llb.Mkfile("/usr/bin/dnf", 0o755, []byte(updateCheckTestTool))).
			File(llb.Mkfile(updatesAvailableMarker, 0o644, []byte("stale marker"))).
			AddEnv("CHECK_CALLS", "/copa-check-calls")

		type buildKitCase struct {
			name        string
			status      int
			output      string
			diagnostics string
			noUpdates   bool
			wantStatus  int
		}
		for _, manager := range []string{testYUM, testDNF, testTDNF, testMicroDNF, testAPK, testAPT, testPacman} {
			noUpdatesStatus, updatesStatus := 0, 0
			updatesOutput := "example 1.2.3\n"
			switch manager {
			case testYUM, testDNF, testMicroDNF:
				updatesStatus = 100
			case testAPT:
				updatesOutput = "Inst example [1.0] (1.2.3 repository [amd64])\n"
			case testPacman:
				noUpdatesStatus = 1
			}
			tests := []buildKitCase{
				{"no updates", noUpdatesStatus, "", "", true, 0},
				{"updates available", updatesStatus, updatesOutput, "", false, 0},
				{"repository failure", 1, "", "SSL certificate verification failed\n", false, 1},
				{"partial failure", 1, updatesOutput, "failed to synchronize one repository\n", false, 1},
			}
			if manager == testAPT {
				tests = append(tests, buildKitCase{"resolver failure", 100, "", "E: Unmet dependencies\n", false, 100})
			}
			for _, tc := range tests {
				t.Run(manager+"/"+tc.name, func(t *testing.T) {
					state := base.
						AddEnv("CHECK_STATUS", strconv.Itoa(tc.status)).
						AddEnv("CHECK_OUTPUT", tc.output).
						AddEnv("CHECK_DIAGNOSTICS", tc.diagnostics).
						AddEnv("CHECK_FAIL_STAGE", "")
					err := checkAvailableUpdates(ctx, client, &state, manager, tool)
					switch {
					case tc.noUpdates:
						require.ErrorIs(t, err, types.ErrNoUpdatesFound)
					case tc.wantStatus != 0:
						require.NotErrorIs(t, err, types.ErrNoUpdatesFound)
						var buildErr *buildkit.ReadFileErr
						require.ErrorAs(t, err, &buildErr)
						require.True(t, buildErr.SolveFailed)
						require.Contains(t, err.Error(), fmt.Sprintf("exit code: %d", tc.wantStatus))
					default:
						require.NoError(t, err)
					}
				})
			}
		}
		return &gwclient.Result{}, nil
	}, nil)
	require.NoError(t, err)
}

type updateCheckResultClient struct {
	gwclient.Client
	result *gwclient.Result
}

//nolint:gocritic // gwclient.Client requires SolveRequest to be passed by value.
func (c *updateCheckResultClient) Solve(ctx context.Context, req gwclient.SolveRequest) (*gwclient.Result, error) {
	result, err := c.Client.Solve(ctx, req)
	c.result = result
	return result, err
}

func TestUpdateCheckRunsForEachBuildWithBuildKit(t *testing.T) {
	addr := os.Getenv("COPA_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("COPA_BUILDKIT_ADDR is required for BuildKit integration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	const tool = "/usr/local/bin/copa-check-test-tool"
	const executionFile = "/copa-check-execution"
	// The fixture always reports no updates, but records each actual execution.
	// Its inputs remain identical across builds, as they do when only remote
	// repository contents change between two patch requests for the same image.
	const script = `#!/bin/sh
if [ "$1" = -q ]; then
    cat /proc/sys/kernel/random/uuid > /copa-check-execution
fi
`
	base := llb.Image("docker.io/library/alpine:3.20", llb.ResolveModePreferLocal).
		Network(llb.NetModeNone).
		File(llb.Mkfile(tool, 0o755, []byte(script)))

	var executions []string
	for range 2 {
		_, err := client.Build(ctx, bkclient.SolveOpt{}, "copa-update-check-cache-test", func(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
			recorder := &updateCheckResultClient{Client: client}
			err := checkAvailableUpdates(ctx, recorder, &base, testYUM, tool)
			require.ErrorIs(t, err, types.ErrNoUpdatesFound)
			require.NotNil(t, recorder.result)
			ref, err := recorder.result.SingleRef()
			require.NoError(t, err)
			require.NotNil(t, ref)
			execution, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: executionFile})
			require.NoError(t, err)
			require.NotEmpty(t, execution)
			executions = append(executions, string(execution))
			return &gwclient.Result{}, nil
		}, nil)
		require.NoError(t, err)
	}
	require.NotEqual(t, executions[0], executions[1], "a previous no-update result must not bypass a new repository check")
}
