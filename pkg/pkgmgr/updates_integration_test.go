//go:build integration

package pkgmgr

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
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

	progress := make(chan *bkclient.SolveStatus)
	var stdout strings.Builder
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		for status := range progress {
			for _, entry := range status.Logs {
				if entry.Stream == 1 {
					stdout.Write(entry.Data)
				}
			}
		}
	}()

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
				{"stdout-only failure", 42, "stdout failure from " + manager + "\n", "", false, 42},
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
	}, progress)
	<-progressDone
	require.NoError(t, err)
	for _, manager := range []string{testYUM, testDNF, testTDNF, testMicroDNF, testAPK, testAPT, testPacman} {
		require.Contains(t, stdout.String(), "stdout failure from "+manager, "BuildKit must receive failed query stdout")
	}
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

func TestRPMInstallRunsForEachBuildWithBuildKit(t *testing.T) {
	addr := os.Getenv("COPA_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("COPA_BUILDKIT_ADDR is required for BuildKit integration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	// Model metadata inherited from the image separately from the metadata
	// refreshed by the detached update check. The install must refresh its own
	// metadata and execute again even when its image and command are unchanged.
	const script = `#!/bin/sh
set -eu
case "$1" in
    install) ;;
    clean) rm -f /copa-repository-cache ;;
    makecache) cat /proc/sys/kernel/random/uuid > /copa-repository-cache ;;
    -q) exit 100 ;;
    upgrade|update)
        if [ "${2:-}" = --refresh ]; then
            rm -f /copa-repository-cache
        fi
        if [ ! -f /copa-repository-cache ]; then
            cat /proc/sys/kernel/random/uuid > /copa-repository-cache
        fi
        cp /copa-repository-cache /copa-metadata-used
        cat /proc/sys/kernel/random/uuid > /copa-install-execution
        ;;
    *) exit 42 ;;
esac
`
	base := llb.Image("docker.io/library/alpine:3.20", llb.ResolveModePreferLocal).
		Network(llb.NetModeNone).
		File(llb.Mkfile("/copa-repository-cache", 0o644, []byte("stale metadata")))
	for _, manager := range []string{testYUM, testDNF, testTDNF, testMicroDNF} {
		base = base.File(llb.Mkfile("/usr/bin/"+manager, 0o755, []byte(script)))
	}

	for _, manager := range []string{testYUM, testDNF, testTDNF, testMicroDNF} {
		t.Run(manager, func(t *testing.T) {
			var executions, metadata []string
			for range 2 {
				_, err := client.Build(ctx, bkclient.SolveOpt{}, "copa-rpm-install-cache-test", func(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
					rm := &rpmManager{
						config:   &buildkit.Config{Client: client, ImageState: base},
						rpmTools: rpmToolPaths{manager: "/usr/bin/" + manager},
					}
					patched, _, err := rm.installUpdates(ctx, nil, false)
					require.NoError(t, err)
					require.NotNil(t, patched)
					definition, err := patched.Marshal(ctx)
					require.NoError(t, err)
					result, err := client.Solve(ctx, gwclient.SolveRequest{Definition: definition.ToPB(), Evaluate: true})
					require.NoError(t, err)
					ref, err := result.SingleRef()
					require.NoError(t, err)
					require.NotNil(t, ref)
					execution, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: "/copa-install-execution"})
					require.NoError(t, err)
					require.NotEmpty(t, execution)
					executions = append(executions, string(execution))
					used, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: "/copa-metadata-used"})
					require.NoError(t, err)
					require.NotEmpty(t, used)
					require.NotEqual(t, "stale metadata", string(used), "the install must not use metadata inherited from the image")
					metadata = append(metadata, string(used))
					_, err = ref.ReadFile(ctx, gwclient.ReadRequest{Filename: updatesAvailableMarker})
					require.ErrorContains(t, err, "no such file or directory", "the update-check marker must not enter the patched image")
					return &gwclient.Result{}, nil
				}, nil)
				require.NoError(t, err)
			}
			require.NotEqual(t, executions[0], executions[1], "each patch request must execute the upgrade")
			require.NotEqual(t, metadata[0], metadata[1], "each upgrade must refresh repository metadata")
		})
	}
}

func TestRPMExternalChecksRunForEachBuildWithBuildKit(t *testing.T) {
	addr := os.Getenv("COPA_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("COPA_BUILDKIT_ADDR is required for BuildKit integration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	for _, manager := range []string{testRPMDistroless, "zypper", "dnf"} {
		t.Run(manager, func(t *testing.T) {
			op, ignoreCache := rpmExternalCheckOperation(t, manager, false)
			// Replay the generated command and cache policy with controlled tools.
			// Keeping the inputs identical exposes cache reuse across builds.
			state := llb.Image("docker.io/library/bash:5.2", llb.ResolveModePreferLocal).
				Network(llb.NetModeNone).
				Dir(op.Meta.Cwd).
				File(llb.Mkdir(op.Meta.Cwd, 0o755, llb.WithParents(true))).
				AddEnv("CHECK_STATUS", "0").
				AddEnv("CHECK_DIAGNOSTICS", "").
				AddEnv("CHECK_EXECUTION_FILE", "/copa-check-execution")
			for _, tool := range []string{"tdnf", "dnf", "zypper"} {
				state = state.File(llb.Mkfile("/usr/local/bin/"+tool, 0o755, []byte(rpmExternalCheckTestTool)))
			}
			state = state.File(llb.Mkfile("/usr/local/bin/rpm", 0o755, []byte("#!/bin/sh\nprintf 'example\\t1.0\\tx86_64\\n'\n")))
			output := "Nothing to do.\n"
			if manager == testRPMDistroless {
				output = "example.x86_64 1.0 repository\n"
			}
			state = state.AddEnv("CHECK_OUTPUT", output)
			var marker string
			for _, env := range op.Meta.Env {
				key, value, ok := strings.Cut(env, "=")
				require.True(t, ok)
				state = state.AddEnv(key, value)
				if key == "COPA_UPDATES_MARKER" {
					marker = value
				}
			}
			require.NotEmpty(t, marker)
			state = state.File(llb.Mkfile(marker, 0o644, []byte("stale marker")))
			opts := []llb.RunOption{llb.Args(op.Meta.Args)}
			if ignoreCache {
				opts = append(opts, llb.IgnoreCache)
			}
			run := state.Run(opts...)
			for _, mount := range op.Mounts {
				if mount.Dest == rpmChrootDir {
					target := llb.Scratch().
						File(llb.Mkdir("/tmp", 0o755)).
						File(llb.Mkdir("/var/lib/rpm", 0o755, llb.WithParents(true))).
						File(llb.Mkfile("/var/lib/rpm/Packages.db", 0o644, nil))
					run.AddMount(mount.Dest, target)
				}
			}
			checked := run.Root()
			var executions []string
			for range 2 {
				_, err := client.Build(ctx, bkclient.SolveOpt{}, "copa-rpm-external-cache-test", func(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
					recorder := &updateCheckResultClient{Client: client}
					err := checkUpdatesMarker(ctx, recorder, &checked, marker)
					require.ErrorIs(t, err, types.ErrNoUpdatesFound)
					require.NotNil(t, recorder.result)
					ref, err := recorder.result.SingleRef()
					require.NoError(t, err)
					require.NotNil(t, ref)
					execution, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: "/copa-check-execution"})
					require.NoError(t, err)
					require.NotEmpty(t, execution)
					executions = append(executions, string(execution))
					return &gwclient.Result{}, nil
				}, nil)
				require.NoError(t, err)
			}
			require.NotEqual(t, executions[0], executions[1], "external RPM checks must observe each build's repository state")
		})
	}
}

// Use a real older APK executable: synthetic tools cannot detect unsupported
// options. No repository access is needed to prove a valid no-update result.
func TestAPKUpdateCheckWithBuildKit(t *testing.T) {
	addr := os.Getenv("COPA_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("COPA_BUILDKIT_ADDR is required for BuildKit integration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	client, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	_, err = client.Build(ctx, bkclient.SolveOpt{}, "copa-apk-compatibility-test", func(ctx context.Context, client gwclient.Client) (*gwclient.Result, error) {
		state := llb.Image("docker.io/library/alpine:3.15.4", llb.ResolveModePreferLocal).
			Network(llb.NetModeNone).
			File(llb.Mkfile(updatesAvailableMarker, 0o644, []byte("stale marker")))
		err := checkAvailableUpdates(ctx, client, &state, testAPK, "/sbin/apk")
		require.ErrorIs(t, err, types.ErrNoUpdatesFound)
		return &gwclient.Result{}, nil
	}, nil)
	require.NoError(t, err)
}
