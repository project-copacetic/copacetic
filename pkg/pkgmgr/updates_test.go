package pkgmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testRPMDistroless = "distroless"
	testAPK           = "apk"
	testAPT           = "apt"
	testYUM           = "yum"
	testDNF           = "dnf"
	testTDNF          = "tdnf"
	testMicroDNF      = "microdnf"
	testPacman        = "pacman"
)

// Exercise each caller, not just the shared marker classifier: a successful
// missing-file read is the only failure that means there are no updates.
func TestUpdateCheckErrors(t *testing.T) {
	type managerCase struct {
		name          string
		marker        string
		initialSolves int
		run           func(*buildkit.Config, bool) (*llb.State, []byte, error)
	}
	managers := []managerCase{
		{
			name: testAPK, marker: "/updates.txt",
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				return (&apkManager{config: cfg}).upgradePackages(t.Context(), nil, ignoreErrors)
			},
		},
		{
			name: testAPT, marker: "/updates.txt",
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				return (&dpkgManager{config: cfg}).installUpdates(t.Context(), nil, ignoreErrors)
			},
		},
		{
			name: testPacman, marker: "/updates.txt",
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				return (&pacmanManager{config: cfg}).upgradePackages(t.Context(), nil, ignoreErrors)
			},
		},
		{
			name: "rpm distroless", marker: "/updates.txt", initialSolves: 2,
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				return (&rpmManager{config: cfg}).unpackAndMergeUpdates(t.Context(), nil, "tooling:latest", nil, ignoreErrors)
			},
		},
		{
			name: "zypper chroot", marker: "/tmp/updates_applied.txt", initialSolves: 1,
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				return (&rpmManager{config: cfg}).zypperChrootInstallUpdates(t.Context(), nil, "tooling:latest", nil, ignoreErrors)
			},
		},
		{
			name: "dnf chroot", marker: "/tmp/updates_applied.txt", initialSolves: 1,
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				return (&rpmManager{config: cfg}).dnfChrootInstallUpdates(t.Context(), nil, "tooling:latest", nil, ignoreErrors)
			},
		},
	}
	for _, tool := range []string{testYUM, testDNF, testTDNF, testMicroDNF} {
		managers = append(managers, managerCase{
			name: tool, marker: "/updates.txt",
			run: func(cfg *buildkit.Config, ignoreErrors bool) (*llb.State, []byte, error) {
				rm := &rpmManager{config: cfg, rpmTools: rpmToolPaths{tool: "/usr/bin/" + tool}}
				return rm.installUpdates(t.Context(), nil, ignoreErrors)
			},
		})
	}

	for _, manager := range managers {
		t.Run(manager.name, func(t *testing.T) {
			for _, ignoreErrors := range []bool{false, true} {
				t.Run(fmt.Sprintf("ignoreErrors=%t", ignoreErrors), func(t *testing.T) {
					for _, scenario := range []struct {
						name       string
						cause      error
						solveError bool
						noUpdates  bool
					}{
						{"missing marker", fmt.Errorf("failed to stat %s: no such file or directory", manager.marker), false, true},
						{"read permission", fmt.Errorf("permission denied: %s", manager.marker), false, false},
						{"read transport", errors.New("connection reset by peer"), false, false},
						{"solve missing command", fmt.Errorf("process creating %s failed: command not found", manager.marker), true, false},
						{"solve canceled", context.Canceled, true, false},
						{"solve deadline", context.DeadlineExceeded, true, false},
					} {
						t.Run(scenario.name, func(t *testing.T) {
							client := new(mocks.MockGWClient)
							ref := new(mocks.MockReference)
							result := &gwclient.Result{}
							result.SetRef(ref)
							for range manager.initialSolves {
								client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
							}
							if manager.initialSolves == 2 {
								ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{Filename: "/applications.txt"}).
									Return([]byte("yum\nrpm\ncpio\nbusybox\n"), nil).Once()
							}
							if scenario.solveError {
								client.On("Solve", mock.Anything, mock.Anything).Return((*gwclient.Result)(nil), scenario.cause).Once()
							} else {
								client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
								ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{Filename: manager.marker}).
									Return([]byte(nil), scenario.cause).Once()
							}

							state, data, err := manager.run(&buildkit.Config{Client: client, ImageState: llb.Scratch()}, ignoreErrors)
							assert.Nil(t, state)
							assert.Nil(t, data)
							if scenario.noUpdates {
								assert.ErrorIs(t, err, types.ErrNoUpdatesFound)
							} else {
								assert.ErrorIs(t, err, scenario.cause)
								assert.NotErrorIs(t, err, types.ErrNoUpdatesFound)
							}
							client.AssertExpectations(t)
							ref.AssertExpectations(t)
						})
					}
				})
			}
		})
	}
}

type updateScriptCase struct {
	manager     string
	status      int
	output      string
	diagnostics string
	failStage   string
	wantStatus  int
	wantUpdates bool
}

const updateCheckTestTool = `#!/bin/sh
printf '%s\n' "$*" >> "$CHECK_CALLS"
case "$1" in
    install|clean|makecache)
        if [ "$1" = "$CHECK_FAIL_STAGE" ]; then
            printf '%s\n' 'repository setup failed' >&2
            exit 42
        fi
        exit 0
        ;;
esac
printf '%s' "$CHECK_OUTPUT"
printf '%s' "$CHECK_DIAGNOSTICS" >&2
exit "$CHECK_STATUS"
`

func runUpdateCheckScript(t *testing.T, tc *updateScriptCase) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is required for script tests")
	}
	workDir := t.TempDir()
	binDir := t.TempDir()
	marker := filepath.Join(workDir, "updates.txt")
	calls := filepath.Join(workDir, "calls.txt")
	// No-update cases must also discard a stale marker from the input image.
	require.NoError(t, os.WriteFile(marker, []byte("old result"), 0o600))

	tool := writeTestExecutable(t, binDir, "package manager", updateCheckTestTool)
	// The microdnf path installs dnf and then invokes it by name.
	writeTestExecutable(t, binDir, testDNF, updateCheckTestTool)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, "-c", checkUpdatesScript, "copa-check-updates", tc.manager, tool, marker)
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TMPDIR="+workDir,
		"CHECK_CALLS="+calls,
		"CHECK_STATUS="+strconv.Itoa(tc.status),
		"CHECK_OUTPUT="+tc.output,
		"CHECK_DIAGNOSTICS="+tc.diagnostics,
		"CHECK_FAIL_STAGE="+tc.failStage,
	)
	output, err := cmd.CombinedOutput()
	if tc.wantStatus == 0 {
		require.NoError(t, err, "script output: %s", output)
	} else {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, "script output: %s", output)
		assert.Equal(t, tc.wantStatus, exitErr.ExitCode(), "script output: %s", output)
		if tc.failStage == "" && tc.output != "" {
			assert.Contains(t, string(output), strings.TrimRight(tc.output, "\n"), "failed queries must preserve stdout")
		}
	}
	if tc.wantUpdates {
		assert.FileExists(t, marker)
	} else {
		assert.NoFileExists(t, marker)
	}
	if tc.failStage != "" {
		assert.Contains(t, string(output), "repository setup failed")
	} else if tc.diagnostics != "" {
		assert.Contains(t, string(output), tc.diagnostics, "package-manager diagnostics must remain visible")
	}
	entries, err := os.ReadDir(workDir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.Contains(t, []string{"calls.txt", "updates.txt"}, entry.Name(), "temporary diagnostics must be cleaned up")
	}
	callLog, err := os.ReadFile(calls)
	require.NoError(t, err)
	return string(callLog)
}

func TestUpdateCheckScript(t *testing.T) {
	for _, manager := range []string{testYUM, testDNF, testTDNF, testMicroDNF, testAPK, testAPT, testPacman} {
		t.Run(manager, func(t *testing.T) {
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
			t.Run("no updates", func(t *testing.T) {
				runUpdateCheckScript(t, &updateScriptCase{manager: manager, status: noUpdatesStatus})
			})
			t.Run("updates available", func(t *testing.T) {
				runUpdateCheckScript(t, &updateScriptCase{
					manager: manager, status: updatesStatus, output: updatesOutput, wantUpdates: true,
				})
			})
			t.Run("failure with stdout only", func(t *testing.T) {
				runUpdateCheckScript(t, &updateScriptCase{
					manager: manager, status: 42, output: "repository lookup failed on stdout\n", wantStatus: 42,
				})
			})
			t.Run("repository failure", func(t *testing.T) {
				runUpdateCheckScript(t, &updateScriptCase{
					manager: manager, status: 1, diagnostics: "SSL certificate verification failed\n", wantStatus: 1,
				})
			})
			t.Run("failure with partial update output", func(t *testing.T) {
				runUpdateCheckScript(t, &updateScriptCase{
					manager: manager, status: 1, output: updatesOutput,
					diagnostics: "failed to synchronize one repository\n", wantStatus: 1,
				})
			})
			t.Run("missing command", func(t *testing.T) {
				runUpdateCheckScript(t, &updateScriptCase{
					manager: manager, status: 127, diagnostics: "command not found\n", wantStatus: 127,
				})
			})
		})
	}

	t.Run("apt exit 100 is an error", func(t *testing.T) {
		runUpdateCheckScript(t, &updateScriptCase{
			manager: testAPT, status: 100, diagnostics: "E: Unmet dependencies\n", wantStatus: 100,
		})
	})
	t.Run("apt successful output without installs", func(t *testing.T) {
		runUpdateCheckScript(t, &updateScriptCase{
			manager: testAPT, output: "Reading package lists...\n0 upgraded, 0 newly installed\n",
		})
	})
	t.Run("rpm exit 100 without stdout", func(t *testing.T) {
		runUpdateCheckScript(t, &updateScriptCase{manager: testDNF, status: 100, wantUpdates: true})
	})
	t.Run("pacman no matches with diagnostics is an error", func(t *testing.T) {
		runUpdateCheckScript(t, &updateScriptCase{
			manager: testPacman, status: 1, diagnostics: "error: could not open database\n", wantStatus: 1,
		})
	})
	t.Run("pacman failure with partial stdout only", func(t *testing.T) {
		runUpdateCheckScript(t, &updateScriptCase{manager: testPacman, status: 1, output: "example 1 -> 2\n", wantStatus: 1})
	})
	t.Run("pacman successful query preserves warnings", func(t *testing.T) {
		runUpdateCheckScript(t, &updateScriptCase{
			manager: testPacman, output: "example 1 -> 2\n", diagnostics: "warning: ignored package\n", wantUpdates: true,
		})
	})
}

func TestRPMUpdateCheckStopsAfterSetupFailure(t *testing.T) {
	for _, manager := range []string{testYUM, testDNF, testTDNF, testMicroDNF} {
		stages := []string{"clean", "makecache"}
		if manager == testMicroDNF {
			stages = append(stages, "install")
		}
		for _, stage := range stages {
			t.Run(manager+"/"+stage, func(t *testing.T) {
				calls := runUpdateCheckScript(t, &updateScriptCase{
					manager: manager, failStage: stage, status: 100, output: "example 1.2.3\n", wantStatus: 42,
				})
				assert.NotContains(t, calls, "check-update", "must not use stale metadata after setup fails")
				if stage == "install" {
					assert.Equal(t, "install dnf -y", strings.TrimSpace(calls))
				}
			})
		}
	}
}

func TestZypperRefreshFailureStopsUpdate(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to exercise the zypper tooling script")
	}
	client := new(mocks.MockGWClient)
	client.On("Solve", mock.Anything, mock.Anything).Return(&gwclient.Result{}, nil).Once()
	stop := errors.New("stop after recording the install script")
	var script string
	client.On("Solve", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req, ok := args.Get(1).(gwclient.SolveRequest)
		require.True(t, ok)
		for _, data := range req.Definition.Def {
			var op pb.Op
			require.NoError(t, op.UnmarshalVT(data))
			if command := op.GetExec(); command != nil && len(command.Meta.Args) == 3 {
				if strings.Contains(command.Meta.Args[2], "zypper --non-interactive refresh") {
					script = command.Meta.Args[2]
				}
			}
		}
	}).Return((*gwclient.Result)(nil), stop).Once()
	rm := &rpmManager{config: &buildkit.Config{Client: client, ImageState: llb.Scratch()}}
	_, _, err = rm.zypperChrootInstallUpdates(t.Context(), nil, "tooling:latest", nil, false)
	require.ErrorIs(t, err, stop)
	require.NotEmpty(t, script)
	client.AssertExpectations(t)

	workDir := t.TempDir()
	binDir := t.TempDir()
	callLog := filepath.Join(workDir, "calls.txt")
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "Packages.db"), nil, 0o600))
	writeTestExecutable(t, binDir, "zypper", `#!/bin/sh
printf '%s\n' "$*" >> "$ZYPPER_CALLS"
if [ "$2" = refresh ]; then
    printf '%s\n' 'repository certificate verification failed' >&2
    exit 42
fi
exit 99
`)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"COPA_RPM_DB_DIR="+workDir,
		"COPA_CHROOT_DIR="+workDir,
		"COPA_UPDATES_MARKER="+filepath.Join(workDir, "updates.txt"),
		"COPA_MANIFEST_FILE="+filepath.Join(workDir, "manifest"),
		"ZYPPER_CALLS="+callLog,
	)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "script output: %s", output)
	assert.Equal(t, 42, exitErr.ExitCode())
	assert.Contains(t, string(output), "repository certificate verification failed")
	assertFileContent(t, callLog, "--non-interactive refresh\n")
}

// Capture the actual update-check command and cache policy generated by each
// external RPM path. The tests replace only its tooling and target filesystem.
func rpmExternalCheckOperation(t *testing.T, manager string) (*pb.ExecOp, bool) {
	t.Helper()
	client := new(mocks.MockGWClient)
	ref := new(mocks.MockReference)
	result := &gwclient.Result{}
	result.SetRef(ref)
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
	if strings.HasPrefix(manager, testRPMDistroless) {
		client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
		ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{Filename: "/applications.txt"}).
			Return([]byte("yum\nrpm\ncpio\nbusybox\n"), nil).Once()
	}
	matchEnv := "COPA_UPDATES_MARKER="
	if manager == "distroless-install" {
		client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
		ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{Filename: updatesAvailableMarker}).Return([]byte{}, nil).Once()
		matchEnv = "IGNORE_ERRORS="
	}
	stop := errors.New("stop after recording the update check")
	var operation *pb.ExecOp
	var ignoreCache bool
	client.On("Solve", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req, ok := args.Get(1).(gwclient.SolveRequest)
		require.True(t, ok)
		for _, data := range req.Definition.Def {
			var op pb.Op
			require.NoError(t, op.UnmarshalVT(data))
			if command := op.GetExec(); command != nil {
				for _, env := range command.Meta.Env {
					if strings.HasPrefix(env, matchEnv) {
						operation = command
						ignoreCache = req.Definition.Metadata[digest.FromBytes(data).String()].GetIgnoreCache()
					}
				}
			}
		}
	}).Return((*gwclient.Result)(nil), stop).Once()
	rm := &rpmManager{
		config:      &buildkit.Config{Client: client, ImageState: llb.Scratch()},
		packageInfo: map[string]string{"example": "1.0"},
	}
	var err error
	switch manager {
	case testRPMDistroless, "distroless-install":
		_, _, err = rm.unpackAndMergeUpdates(t.Context(), nil, "tooling:latest", nil, false)
	case "zypper":
		_, _, err = rm.zypperChrootInstallUpdates(t.Context(), nil, "tooling:latest", nil, false)
	case "dnf":
		_, _, err = rm.dnfChrootInstallUpdates(t.Context(), nil, "tooling:latest", nil, false)
	default:
		t.Fatalf("unexpected external RPM manager %q", manager)
	}
	require.ErrorIs(t, err, stop)
	require.NotNil(t, operation)
	client.AssertExpectations(t)
	ref.AssertExpectations(t)
	return operation, ignoreCache
}

const rpmExternalCheckTestTool = `#!/bin/sh
for arg in "$@"; do
    case "$arg" in
        list|up|upgrade)
            if [ -n "${CHECK_EXECUTION_FILE:-}" ]; then
                cat /proc/sys/kernel/random/uuid > "$CHECK_EXECUTION_FILE"
            fi
            printf '%s' "$CHECK_OUTPUT"
            printf '%s' "$CHECK_DIAGNOSTICS" >&2
            exit "$CHECK_STATUS"
            ;;
    esac
done
`

func TestRPMExternalUpdateScripts(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to exercise external RPM tooling scripts")
	}
	for _, manager := range []string{testRPMDistroless, "zypper", "dnf"} {
		t.Run(manager, func(t *testing.T) {
			op, _ := rpmExternalCheckOperation(t, manager)
			for _, fail := range []bool{false, true} {
				t.Run(fmt.Sprintf("failure=%t", fail), func(t *testing.T) {
					workDir, binDir := t.TempDir(), t.TempDir()
					marker := filepath.Join(workDir, "updates.txt")
					require.NoError(t, os.WriteFile(marker, []byte("stale marker"), 0o600))
					rpmDB := filepath.Join(workDir, "var", "lib", "rpm")
					require.NoError(t, os.MkdirAll(rpmDB, 0o700))
					require.NoError(t, os.WriteFile(filepath.Join(rpmDB, "Packages.db"), nil, 0o600))
					for _, tool := range []string{"tdnf", "dnf", "zypper"} {
						writeTestExecutable(t, binDir, tool, rpmExternalCheckTestTool)
					}
					// Tooling may provide tdnf without the yum compatibility command.
					writeTestExecutable(t, binDir, "yum", "#!/bin/sh\nexit 127\n")
					writeTestExecutable(t, binDir, "rpm", "#!/bin/sh\nprintf 'example\\t1.0\\tx86_64\\n'\n")
					output := "Nothing to do.\n"
					if manager == testRPMDistroless {
						output = "example.x86_64 1.0 repository\n"
					}
					status, diagnostics := "0", ""
					if fail {
						status, diagnostics = "42", "repository lookup failed\n"
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					// #nosec G204 -- Exercise Copa-generated scripts with fixed synthetic inputs.
					cmd := exec.CommandContext(ctx, bash, "-c", op.Meta.Args[2])
					cmd.Dir = workDir
					cmd.Env = append(os.Environ(),
						"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
						"PACKAGES_PRESENT={\"example\":\"1.0\"}",
						"COPA_RPM_DB_DIR="+rpmDB,
						"COPA_CHROOT_DIR="+workDir,
						"COPA_UPDATES_MARKER="+marker,
						"COPA_MANIFEST_FILE="+filepath.Join(workDir, "manifest"),
						"CHECK_STATUS="+status,
						"CHECK_OUTPUT="+output,
						"CHECK_DIAGNOSTICS="+diagnostics,
					)
					actual, err := cmd.CombinedOutput()
					if fail {
						var exitErr *exec.ExitError
						require.ErrorAs(t, err, &exitErr, "script output: %s", actual)
						assert.Equal(t, 42, exitErr.ExitCode())
						assert.Contains(t, string(actual), diagnostics)
						assert.Contains(t, string(actual), strings.TrimRight(output, "\n"), "failed external checks must preserve stdout")
					} else {
						require.NoError(t, err, "script output: %s", actual)
					}
					require.NoFileExists(t, marker, "a failed or empty check must clear the input marker")
				})
			}
		})
	}
}

func TestRPMDistrolessInstallPreservesFailure(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to exercise the RPM distroless install script")
	}
	op, _ := rpmExternalCheckOperation(t, "distroless-install")
	workDir, binDir := t.TempDir(), t.TempDir()
	rootfs := filepath.Join(workDir, "rootfs")
	rpmDB := filepath.Join(workDir, "rpmdb")
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "packages.txt"), []byte("example"), 0o600))
	writeTestExecutable(t, binDir, "rpm", "#!/bin/sh\nexit 0\n")
	writeTestExecutable(t, binDir, "tdnf", "#!/bin/sh\nprintf 'package download failed\\n' >&2\nexit 42\n")
	// Relocate only the script's fixed scratch paths for safe host execution.
	script := strings.NewReplacer(rpmChrootDir, rootfs, "/tmp/rpmdb", rpmDB).Replace(op.Meta.Args[2])
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-c", script)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"), "IGNORE_ERRORS=false", "OS_VERSION=1.0")
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "script output: %s", output)
	assert.Equal(t, 42, exitErr.ExitCode())
	assert.Contains(t, string(output), "package download failed")
}
