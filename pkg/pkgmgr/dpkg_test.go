package pkgmgr

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func TestExternalDPKGPatchedStateAvoidsNestedMergeGraph(t *testing.T) {
	current := llb.Scratch().
		File(llb.Mkdir(dpkgLibPath, 0o755, llb.WithParents(true))).
		File(llb.Mkfile(dpkgStatusPath, 0o644, []byte("Package: base-files\nVersion: 1\n")))
	updated := current.File(llb.Mkfile(dpkgStatusPath, 0o644, []byte("Package: base-files\nVersion: 2\n")))

	state := externalDPKGPatchedState(&updated)
	def, err := state.Marshal(t.Context())
	require.NoError(t, err)

	mergeOps := 0
	diffOps := 0
	for _, raw := range def.Def {
		var op pb.Op
		require.NoError(t, op.Unmarshal(raw))
		if op.GetMerge() != nil {
			mergeOps++
		}
		if op.GetDiff() != nil {
			diffOps++
		}
	}

	assert.Zero(t, mergeOps, "external dpkg output must remain a linear state so an exported image can be used as the next BuildKit source")
	assert.Zero(t, diffOps, "the updated mount already contains the complete current filesystem")
}

func TestDPKGInstallationModeString(t *testing.T) {
	tests := []struct {
		name string
		mode dpkgInstallationMode
		want string
	}{
		{name: "unknown", mode: dpkgInstallationModeUnknown, want: "unknown"},
		{name: "target tools", mode: dpkgInstallationModeTargetTools, want: "target-dpkg-tools"},
		{name: "external full status", mode: dpkgInstallationModeExternalFullStatus, want: "external-full-status"},
		{name: "external status directory", mode: dpkgInstallationModeExternalStatusDirectory, want: "external-status-directory"},
		{name: "native Chisel", mode: dpkgInstallationModeNativeChisel, want: "native-chisel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.String())
		})
	}
}

func TestClassifyDPKGInstallationMode(t *testing.T) {
	tests := []struct {
		name        string
		probe       dpkgProbeResult
		want        dpkgInstallationMode
		wantErr     bool
		errContains []string
	}{
		{
			name: "native manifest wins over full status and tools",
			probe: dpkgProbeResult{
				hasManifest: true,
				hasStatus:   true,
			},
			want: dpkgInstallationModeNativeChisel,
		},
		{
			name: "native manifest wins over every other format",
			probe: dpkgProbeResult{
				hasManifest:        true,
				hasStatus:          true,
				hasStatusDirectory: true,
				missingTools:       []string{"apt-get", "sh"},
			},
			want: dpkgInstallationModeNativeChisel,
		},
		{
			name: "full status with all tools uses target",
			probe: dpkgProbeResult{
				hasStatus: true,
			},
			want: dpkgInstallationModeTargetTools,
		},
		{
			name: "full status with tools wins over status directory",
			probe: dpkgProbeResult{
				hasStatus:          true,
				hasStatusDirectory: true,
			},
			want: dpkgInstallationModeTargetTools,
		},
		{
			name: "full status missing any tool uses external tooling",
			probe: dpkgProbeResult{
				hasStatus:    true,
				missingTools: []string{"tee"},
			},
			want: dpkgInstallationModeExternalFullStatus,
		},
		{
			name: "full status missing tools wins over status directory",
			probe: dpkgProbeResult{
				hasStatus:          true,
				hasStatusDirectory: true,
				missingTools:       []string{"apt-get", "dpkg"},
			},
			want: dpkgInstallationModeExternalFullStatus,
		},
		{
			name: "status directory uses external tooling",
			probe: dpkgProbeResult{
				hasStatusDirectory: true,
			},
			want: dpkgInstallationModeExternalStatusDirectory,
		},
		{
			name:        "unsupported metadata names every checked path",
			want:        dpkgInstallationModeUnknown,
			wantErr:     true,
			errContains: []string{chiselManifestPath, dpkgStatusPath, dpkgStatusFolder},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyDPKGInstallationMode(tt.probe)
			assert.Equal(t, tt.want, got)
			if tt.wantErr {
				assert.Error(t, err)
				for _, expected := range tt.errContains {
					assert.ErrorContains(t, err, expected)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestIsValidDebianVersion(t *testing.T) {
	type args struct {
		v string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid version", args{"1.0"}, true},
		{"invalid version", args{"a.b"}, false},
		{"valid version with suffix", args{"1.0-r0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDebianVersion(tt.args.v); got != tt.want {
				t.Errorf("isValidDebianVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDebianVersionOrdering(t *testing.T) {
	tests := []struct {
		name  string
		older string
		newer string
	}{
		{name: "revision", older: "1.0-1", newer: "1.0-2"},
		{name: "tilde sorts before release", older: "1.0~rc1-1", newer: "1.0-1"},
		{name: "epoch", older: "1:99.0-1", newer: "2:1.0-1"},
		{name: "Ubuntu revision", older: "2.39-0ubuntu8.4", newer: "2.39-0ubuntu8.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, isLessThanDebianVersion(tt.older, tt.newer))
			assert.False(t, isLessThanDebianVersion(tt.newer, tt.older))
			assert.False(t, isLessThanDebianVersion(tt.older, tt.older))
		})
	}
}

func TestMarshalDPKGPackageVersions(t *testing.T) {
	data, err := marshalDPKGPackageVersions(map[string]string{
		"zlib1g":     "1:1.3.dfsg+really1.3.1-1ubuntu1",
		"base-files": "13ubuntu10.2",
	}, map[string]struct{}{"zlib1g": {}})
	assert.NoError(t, err)
	assert.Equal(t, "base-files|13ubuntu10.2|install\nzlib1g|1:1.3.dfsg+really1.3.1-1ubuntu1|hold\n", string(data))

	_, err = marshalDPKGPackageVersions(map[string]string{"bad;touch": "1.0"}, nil)
	assert.ErrorContains(t, err, "invalid package name")

	_, err = marshalDPKGPackageVersions(map[string]string{"base-files": "$(touch /tmp/pwned)"}, nil)
	assert.ErrorContains(t, err, "invalid installed version")
}

func TestGetAPTImageName(t *testing.T) {
	tests := []struct {
		name           string
		osType         string
		osVersion      string
		useCachePrefix bool
		want           string
	}{
		{
			name:           "no-report Ubuntu uses detected Ubuntu release",
			osType:         utils.OSTypeUbuntu,
			osVersion:      "24.04",
			useCachePrefix: true,
			want:           "ghcr.io/project-copacetic/copacetic/ubuntu:24.04",
		},
		{
			name:           "Debian point release uses major slim tag",
			osType:         utils.OSTypeDebian,
			osVersion:      "11.1",
			useCachePrefix: true,
			want:           "ghcr.io/project-copacetic/copacetic/debian:11-slim",
		},
		{
			name:      "newer Debian uses stable slim",
			osType:    utils.OSTypeDebian,
			osVersion: "13",
			want:      "debian:stable-slim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getAPTImageName(tt.osType, tt.osVersion, tt.useCachePrefix))
		})
	}
}

func TestParseDPKGProbeResult(t *testing.T) {
	got, err := parseDPKGProbeResult([]byte("manifest=0\nstatus=1\nstatus_directory=1\nmissing_tools=apt-get tee\n"))
	assert.NoError(t, err)
	assert.Equal(t, dpkgProbeResult{
		hasStatus:          true,
		hasStatusDirectory: true,
		missingTools:       []string{"apt-get", "tee"},
	}, got)

	_, err = parseDPKGProbeResult([]byte("manifest=maybe\nstatus=1\nstatus_directory=0\nmissing_tools=\n"))
	assert.ErrorContains(t, err, "invalid value")
}

var (
	//go:embed testdata/dpkg_valid.txt
	validDPKGManifest []byte

	// initialized to `nil`; tests error handling.
	nonExistingManifest []byte

	//go:embed testdata/empty.txt
	emptyManifest []byte

	//go:embed testdata/invalid.txt
	invalidDPKGManifest []byte

	//go:embed testdata/dpkg_full_status.txt
	fullDPKGStatus []byte
)

func TestParseDPKGStatus(t *testing.T) {
	input := bytes.Clone(fullDPKGStatus)
	parsed, err := parseDPKGStatus(input)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{
		"base-files": "13ubuntu10.2",
		"libc6":      "2.39-0ubuntu8.5",
		"tzdata":     "2025b-0ubuntu0.24.04.1",
	}, parsed.packages)
	assert.Equal(t, map[string]struct{}{"tzdata": {}}, parsed.heldPackages)
	assert.Equal(t, fullDPKGStatus, parsed.contents)
	assert.Contains(t, string(parsed.databaseContents), "Status: install ok installed")

	// The retained status must not alias the extraction buffer because it is
	// used later to reconstruct the temporary dpkg database verbatim.
	input[0] = 'X'
	assert.Equal(t, fullDPKGStatus, parsed.contents)
}

func TestParseDPKGStatusExcludesRemovedPackages(t *testing.T) {
	status := []byte("Package: installed\nStatus: install ok installed\nVersion: 1.0\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 2.0\n")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"installed": "1.0"}, parsed.packages)
	assert.Equal(t, status, parsed.contents)
}

func TestParseDPKGStatusAllowsNotInstalledPackageWithoutVersion(t *testing.T) {
	status := []byte("Package: installed\nStatus: install ok installed\nVersion: 1.0\n\nPackage: gnupg\nStatus: purge ok not-installed\n")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"installed": "1.0"}, parsed.packages)
	assert.Empty(t, parsed.heldPackages)
	assert.Equal(t, status, parsed.contents)
}

func TestParseDPKGStatusAcceptsInventoryWithoutStatusFields(t *testing.T) {
	status := []byte("Package: base-files\nVersion: 13ubuntu10.2\nArchitecture: amd64\n\nPackage: libc6\nVersion: 2.39-0ubuntu8.4\nArchitecture: amd64\n")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{
		"base-files": "13ubuntu10.2",
		"libc6":      "2.39-0ubuntu8.4",
	}, parsed.packages)
	assert.Equal(t, status, parsed.contents)
	expectedDatabase := strings.Join([]string{
		"Package: base-files",
		"Status: install ok installed",
		"Version: 13ubuntu10.2",
		"Architecture: amd64",
		"",
		"Package: libc6",
		"Status: install ok installed",
		"Version: 2.39-0ubuntu8.4",
		"Architecture: amd64",
		"",
		"",
	}, "\n")
	assert.Equal(t, expectedDatabase, string(parsed.databaseContents))
}

func TestParseDPKGStatusErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		wantErr string
	}{
		{name: "empty", status: "", wantErr: "no package paragraphs"},
		{name: "missing package", status: "Status: install ok installed\nVersion: 1.0\n", wantErr: "no Package field"},
		{name: "missing version", status: "Package: base-files\nStatus: install ok installed\n", wantErr: "no Version field"},
		{name: "invalid package", status: "Package: -option\nStatus: install ok installed\nVersion: 1.0\n", wantErr: "invalid package name"},
		{name: "invalid version", status: "Package: base-files\nStatus: install ok installed\nVersion: invalid version\n", wantErr: "invalid version"},
		{name: "invalid status", status: "Package: base-files\nStatus: installed\nVersion: 1.0\n", wantErr: "invalid status"},
		{name: "malformed field", status: "Package: base-files\nStatus: install ok installed\nnot-a-field\nVersion: 1.0\n", wantErr: "malformed field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDPKGStatus([]byte(tt.status))
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParseDPKGStatusAcceptsCRLFAndNoFinalNewline(t *testing.T) {
	status := []byte("Package: base-files\r\nStatus: install ok installed\r\nVersion: 1.0")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"base-files": "1.0"}, parsed.packages)
	assert.Equal(t, status, parsed.contents)
}

func runEmbeddedShellScript(t *testing.T, script []byte, env map[string]string) []byte {
	t.Helper()

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is required for script tests")
	}
	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	assert.NoError(t, os.WriteFile(scriptPath, script, 0o600))
	assert.NoError(t, os.Chmod(scriptPath, 0o700))

	cmd := exec.Command(sh, scriptPath)
	cmd.Env = os.Environ()
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output, err := cmd.CombinedOutput()
	if !assert.NoError(t, err, "script output: %s", output) {
		t.FailNow()
	}
	return output
}

func writeTestExecutable(t *testing.T, dir, name, contents string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	assert.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	assert.NoError(t, os.Chmod(path, 0o700))
	return path
}

func TestSelectDPKGUpdatesScriptOnlySelectsStrictlyNewerCandidates(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	installedPath := filepath.Join(workDir, "installed-packages")
	packagesPath := filepath.Join(workDir, "packages.txt")
	markerPath := filepath.Join(workDir, "updates.txt")
	compareLog := filepath.Join(workDir, "compare.log")

	installedData, err := marshalDPKGPackageVersions(map[string]string{
		"epoch":   "1:99.0-1",
		"equal":   "1.0-1",
		"held":    "1.0-1",
		"missing": "1.0-1",
		"newer":   "1.0~rc1-1",
		"older":   "2.0-1",
	}, map[string]struct{}{"held": {}})
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(installedPath, installedData, 0o600))

	writeTestExecutable(t, binDir, "apt-cache", `#!/bin/sh
case "$2" in
    epoch) candidate='2:1.0-1' ;;
    equal) candidate='1.0-1' ;;
    missing) candidate='(none)' ;;
    newer) candidate='1.0-1' ;;
    older) candidate='1.9-1' ;;
    *) exit 2 ;;
esac
printf '  Candidate: %s\n' "$candidate"
`)
	writeTestExecutable(t, binDir, "dpkg", `#!/bin/sh
printf '%s|%s|%s\n' "$2" "$3" "$4" >> "$COMPARE_LOG"
case "$2|$3|$4" in
    '2:1.0-1|gt|1:99.0-1'|'1.0-1|gt|1.0~rc1-1') exit 0 ;;
    '1.0-1|gt|1.0-1'|'1.9-1|gt|2.0-1') exit 1 ;;
    *) exit 2 ;;
esac
`)

	runEmbeddedShellScript(t, selectDPKGUpdatesScript, map[string]string{
		"PATH":                    binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"COMPARE_LOG":             compareLog,
		"INSTALLED_PACKAGES_FILE": installedPath,
		"UPDATE_PACKAGES_FILE":    packagesPath,
		"UPDATES_MARKER_FILE":     markerPath,
	})

	selected, err := os.ReadFile(packagesPath)
	assert.NoError(t, err)
	assert.Equal(t, "epoch\nnewer\n", string(selected))
	assert.FileExists(t, markerPath)

	comparisons, err := os.ReadFile(compareLog)
	assert.NoError(t, err)
	assert.Equal(t, strings.Join([]string{
		"2:1.0-1|gt|1:99.0-1",
		"1.0-1|gt|1.0-1",
		"1.0-1|gt|1.0~rc1-1",
		"1.9-1|gt|2.0-1",
	}, "\n")+"\n", string(comparisons))
}

func TestAptGetDownloadScriptSkipsUnsafeTargetedVersions(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	downloadDir := filepath.Join(workDir, "downloads")
	dpkgRoot := filepath.Join(workDir, "rootfs")
	packagesPath := filepath.Join(workDir, "packages.txt")
	floorsPath := filepath.Join(workDir, "version-floors")
	finalizePath := filepath.Join(workDir, "finalize_dpkg_status.sh")
	installLog := filepath.Join(workDir, "install.log")

	assert.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "info"), 0o755))
	assert.NoError(t, os.WriteFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"), fullDPKGStatus, 0o600))
	assert.NoError(t, os.WriteFile(packagesPath, []byte("safe\ndowngrade\nbelow-fixed\n"), 0o600))
	assert.NoError(t, os.WriteFile(floorsPath, []byte("safe|1.0|2.0\ndowngrade|3.0|2.0\nbelow-fixed|1.0|3.0\n"), 0o600))
	assert.NoError(t, os.WriteFile(finalizePath, finalizeDPKGStatusScript, 0o600))
	assert.NoError(t, os.Chmod(finalizePath, 0o700))

	writeTestExecutable(t, binDir, "apt-get", `#!/bin/sh
mode=''
after_separator=false
for arg in "$@"; do
    case "$arg" in
        update) exit 0 ;;
        download|install) mode=download ;;
        --) after_separator=true ;;
        *)
            if [ "$mode" = download ] && [ "$after_separator" = true ]; then
                : > "./$arg.deb"
            fi
            ;;
    esac
done
`)
	writeTestExecutable(t, binDir, "dpkg-deb", `#!/bin/sh
case "$1" in
    -R)
        mkdir -p "$3/DEBIAN"
        exit 0
        ;;
    -b)
        : > "$3"
        exit 0
        ;;
    -f)
        package=${2##*/}
        package=${package%.deb}
        case "$3" in
            Package) printf '%s\n' "$package" ;;
            Version)
                case "$package" in
                    safe) printf '2.1\n' ;;
                    downgrade) printf '2.5\n' ;;
                    below-fixed) printf '2.0\n' ;;
                    *) exit 2 ;;
                esac
                ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg", `#!/bin/sh
if [ "$1" = '--compare-versions' ]; then
    case "$2|$3|$4" in
        '2.1|ge|1.0'|'2.1|ge|2.0'|'2.5|ge|2.0'|'2.0|ge|1.0') exit 0 ;;
        '2.5|ge|3.0'|'2.0|ge|3.0') exit 1 ;;
        *) exit 2 ;;
    esac
fi
printf '%s\n' "$*" >> "$INSTALL_LOG"
`)

	runEmbeddedShellScript(t, aptGetDownloadScript, map[string]string{
		"PATH":                        binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"IGNORE_ERRORS":               "true",
		"UPDATE_ALL":                  "false",
		"DPKG_ROOT":                   dpkgRoot,
		"DOWNLOAD_DIR":                downloadDir,
		"PACKAGES_FILE":               packagesPath,
		"VERSION_FLOORS_FILE":         floorsPath,
		"FINALIZE_DPKG_STATUS_SCRIPT": finalizePath,
		"DPKG_INSTALLATION_MODE":      dpkgInstallationModeExternalFullStatus.String(),
		"STATUSD_FILE_MAP":            "{}",
		"INSTALL_LOG":                 installLog,
	})

	installArgs, err := os.ReadFile(installLog)
	assert.NoError(t, err)
	assert.Contains(t, string(installArgs), "safe.deb")
	assert.NotContains(t, string(installArgs), "downgrade.deb")
	assert.NotContains(t, string(installArgs), "below-fixed.deb")
	assert.FileExists(t, filepath.Join(downloadDir, "safe.deb"))
	assert.NoFileExists(t, filepath.Join(downloadDir, "downgrade.deb"))
	assert.NoFileExists(t, filepath.Join(downloadDir, "below-fixed.deb"))

	manifest, err := os.ReadFile(filepath.Join(dpkgRoot, "manifest"))
	assert.NoError(t, err)
	errorPkgs, err := validateDebianPackageVersions(
		unversioned.UpdatePackages{
			{Name: "safe", FixedVersion: "2.0"},
			{Name: "downgrade", FixedVersion: "2.0"},
			{Name: "below-fixed", FixedVersion: "3.0"},
		},
		map[string]string{"safe": "1.0", "downgrade": "3.0", "below-fixed": "1.0"},
		VersionComparer{isValidDebianVersion, isLessThanDebianVersion},
		manifest,
		true,
	)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"downgrade", "below-fixed"}, errorPkgs)

	assert.FileExists(t, filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"))
	assert.NoDirExists(t, filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status.d"))
}

func TestDPKGProbeScriptDoesNotExecuteTargetTools(t *testing.T) {
	targetRoot := t.TempDir()
	resultsDir := t.TempDir()
	toolDir := filepath.Join(targetRoot, "usr", "bin")
	assert.NoError(t, os.MkdirAll(toolDir, 0o755))

	markerPath := filepath.Join(t.TempDir(), "target-tool-executed")
	fakeTool := []byte("#!/bin/sh\nprintf executed > \"$MARKER_PATH\"\n")
	for _, tool := range requiredDPKGTools {
		toolPath := filepath.Join(toolDir, tool)
		assert.NoError(t, os.WriteFile(toolPath, fakeTool, 0o600))
		assert.NoError(t, os.Chmod(toolPath, 0o700))
	}

	statusPath := filepath.Join(targetRoot, strings.TrimPrefix(dpkgStatusPath, "/"))
	assert.NoError(t, os.MkdirAll(filepath.Dir(statusPath), 0o755))
	assert.NoError(t, os.WriteFile(statusPath, fullDPKGStatus, 0o600))

	probeOutputPath := filepath.Join(resultsDir, dpkgProbeOutputFilename)
	copiedStatusPath := filepath.Join(resultsDir, dpkgStatusOutputFilename)
	runEmbeddedShellScript(t, probeDPKGScript, map[string]string{
		"TARGET_ROOT":               targetRoot,
		"MARKER_PATH":               markerPath,
		"CHISEL_MANIFEST_PATH":      chiselManifestPath,
		"DPKG_STATUS_PATH":          dpkgStatusPath,
		"DPKG_STATUS_FOLDER":        dpkgStatusFolder,
		"REQUIRED_DPKG_TOOLS":       strings.Join(requiredDPKGTools, " "),
		"RESULTS_PATH":              resultsDir,
		"RESULT_STATUS_PATH":        copiedStatusPath,
		"RESULT_STATUSD_LIST_PATH":  filepath.Join(resultsDir, dpkgStatusdListFilename),
		"RESULT_STATUSD_FILES_PATH": filepath.Join(resultsDir, dpkgStatusdFilesFolder),
		"PROBE_OUTPUT_PATH":         probeOutputPath,
	})

	probeBytes, err := os.ReadFile(probeOutputPath)
	assert.NoError(t, err)
	probe, err := parseDPKGProbeResult(probeBytes)
	assert.NoError(t, err)
	assert.True(t, probe.hasStatus)
	assert.Empty(t, probe.missingTools)
	mode, err := classifyDPKGInstallationMode(probe)
	assert.NoError(t, err)
	assert.Equal(t, dpkgInstallationModeTargetTools, mode)

	copiedStatus, err := os.ReadFile(copiedStatusPath)
	assert.NoError(t, err)
	assert.Equal(t, fullDPKGStatus, copiedStatus)
	assert.NoFileExists(t, markerPath, "the probe must not execute target apt/dpkg/shell utilities")
}

func TestFinalizeDPKGStatusScript(t *testing.T) {
	t.Run("full status remains a full status file", func(t *testing.T) {
		root := t.TempDir()
		dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
		assert.NoError(t, os.MkdirAll(filepath.Join(dpkgDir, "info"), 0o755))
		assert.NoError(t, os.MkdirAll(filepath.Join(dpkgDir, "status.d"), 0o755))
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "status"), fullDPKGStatus, 0o644)
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "info", "temporary.list"), []byte("temporary"), 0o644)
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "status.d", "old"), []byte("old"), 0o644)

		runEmbeddedShellScript(t, finalizeDPKGStatusScript, map[string]string{
			"DPKG_ROOT":              root,
			"DPKG_INSTALLATION_MODE": dpkgInstallationModeExternalFullStatus.String(),
			"STATUSD_FILE_MAP":       "{}",
		})

		status, err := os.ReadFile(filepath.Join(dpkgDir, "status"))
		assert.NoError(t, err)
		assert.Equal(t, fullDPKGStatus, status)
		entries, err := os.ReadDir(dpkgDir)
		assert.NoError(t, err)
		assert.Equal(t, []string{"status"}, directoryEntryNames(entries))
		assert.NoDirExists(t, filepath.Join(dpkgDir, "status.d"))
	})

	t.Run("status directory behavior is preserved", func(t *testing.T) {
		root := t.TempDir()
		dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
		assert.NoError(t, os.MkdirAll(filepath.Join(dpkgDir, "info"), 0o755))
		status := "Package: base-files\nStatus: install ok installed\nVersion: 1.0\n\nPackage: tzdata\nStatus: install ok installed\nVersion: 2.0\n"
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "status"), []byte(status), 0o644)
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "info", "temporary.list"), []byte("temporary"), 0o644)

		runEmbeddedShellScript(t, finalizeDPKGStatusScript, map[string]string{
			"DPKG_ROOT":              root,
			"DPKG_INSTALLATION_MODE": dpkgInstallationModeExternalStatusDirectory.String(),
			"STATUSD_FILE_MAP":       `{"base-files":"encoded-base-files"}`,
		})

		entries, err := os.ReadDir(dpkgDir)
		assert.NoError(t, err)
		assert.Equal(t, []string{"status.d"}, directoryEntryNames(entries))
		assert.NoFileExists(t, filepath.Join(dpkgDir, "status"))

		statusdEntries, err := os.ReadDir(filepath.Join(dpkgDir, "status.d"))
		assert.NoError(t, err)
		assert.Equal(t, []string{"encoded-base-files", "tzdata"}, directoryEntryNames(statusdEntries))
		baseFiles, err := os.ReadFile(filepath.Join(dpkgDir, "status.d", "encoded-base-files"))
		assert.NoError(t, err)
		assert.Contains(t, string(baseFiles), "Package: base-files")
		tzdata, err := os.ReadFile(filepath.Join(dpkgDir, "status.d", "tzdata"))
		assert.NoError(t, err)
		assert.Contains(t, string(tzdata), "Package: tzdata")
	})
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestDpkgParseResultsManifest(t *testing.T) {
	t.Run("valid manifest", func(t *testing.T) {
		expectedMap := map[string]string{
			"apt-get":    "1.8.2.3",
			"base-files": "10.3+deb10u13",
		}
		actualMap, err := dpkgParseResultsManifest(validDPKGManifest)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(expectedMap, actualMap) {
			t.Fatalf("Expected map: %v, Actual map: %v", expectedMap, actualMap)
		}
	})

	t.Run("non-existing manifest file", func(t *testing.T) {
		expectedErr := fmt.Errorf("%s could not be opened", nonExistingManifest)
		_, actualErr := dpkgParseResultsManifest(nonExistingManifest)
		if errors.Is(actualErr, expectedErr) {
			t.Fatalf("Expected error: %v, Actual error: %v", expectedErr, actualErr)
		}
	})

	t.Run("empty manifest file", func(t *testing.T) {
		expectedMap := map[string]string{}
		actualMap, err := dpkgParseResultsManifest(emptyManifest)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(expectedMap, actualMap) {
			t.Fatalf("Expected map: %v, Actual map: %v", expectedMap, actualMap)
		}
	})

	t.Run("invalid manifest file", func(t *testing.T) {
		expectedErr := fmt.Errorf("unexpected results.manifest file entry: invalid")
		_, actualErr := dpkgParseResultsManifest(invalidDPKGManifest)
		if errors.Is(actualErr, expectedErr) {
			t.Fatalf("Expected error: %v, Actual error: %v", expectedErr, actualErr)
		}
	})
}

func TestValidateDebianPackageVersions(t *testing.T) {
	dpkgComparer := VersionComparer{isValidDebianVersion, isLessThanDebianVersion}

	testCases := []struct {
		name              string
		updates           unversioned.UpdatePackages
		installedVersions map[string]string
		cmp               VersionComparer
		resultsBytes      []byte
		ignoreErrors      bool
		expectedError     string
		expectedErrPkgs   []string
	}{
		{
			name:         "no updates",
			updates:      unversioned.UpdatePackages{},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
		},
		{
			name: "package not installed",
			updates: unversioned.UpdatePackages{
				{Name: "not-installed", FixedVersion: "1.0.0"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
		},
		{
			name: "invalid version",
			updates: unversioned.UpdatePackages{
				{Name: "base-files", FixedVersion: "1.0.0"},
			},
			cmp:           dpkgComparer,
			resultsBytes:  invalidDPKGManifest,
			ignoreErrors:  false,
			expectedError: `unexpected results.manifest file entry`,
		},
		{
			name: "invalid version with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "base-files", FixedVersion: "1.0.0"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: true,
		},
		{
			name: "version lower than requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "2.0"},
			},
			installedVersions: map[string]string{"apt-get": "1.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
			expectedError: `1 error occurred:
	* downloaded package apt-get version 1.8.2.3 lower than required 2.0 for update`,
			expectedErrPkgs: []string{"apt-get"},
		},
		{
			name: "version lower than requested with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "2.0"},
			},
			installedVersions: map[string]string{"apt-get": "1.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      true,
			expectedErrPkgs:   []string{"apt-get"},
		},
		{
			name: "version lower than currently installed",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.0"},
			},
			installedVersions: map[string]string{"apt-get": "2.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
			expectedError: `1 error occurred:
	* downloaded package apt-get version 1.8.2.3 lower than currently installed version 2.0`,
			expectedErrPkgs: []string{"apt-get"},
		},
		{
			name: "version lower than currently installed with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.0"},
			},
			installedVersions: map[string]string{"apt-get": "2.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      true,
			expectedErrPkgs:   []string{"apt-get"},
		},
		{
			name: "version equal to requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.8.2.3"},
			},
			installedVersions: map[string]string{"apt-get": "1.8.2.3"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
		},
		{
			name: "version greater than requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "0.9"},
			},
			installedVersions: map[string]string{"apt-get": "1.8.2.3"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorPkgs, err := validateDebianPackageVersions(tc.updates, tc.installedVersions, tc.cmp, tc.resultsBytes, tc.ignoreErrors)
			if tc.expectedError != "" {
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if tc.expectedErrPkgs != nil {
				if !reflect.DeepEqual(tc.expectedErrPkgs, errorPkgs) {
					t.Errorf("expected error packages %v, got %v", tc.expectedErrPkgs, errorPkgs)
				}
			}
		})
	}
}

func TestGetPackageType(t *testing.T) {
	type fields struct {
		config           *buildkit.Config
		workingFolder    string
		installationMode dpkgInstallationMode
		statusdNames     string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: utils.OSTypeDebian,
			fields: fields{
				config:           &buildkit.Config{},
				workingFolder:    utils.DefaultTempWorkingFolder,
				installationMode: dpkgInstallationModeTargetTools,
				statusdNames:     "",
			},
			want: "deb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &dpkgManager{
				config:           tt.fields.config,
				workingFolder:    tt.fields.workingFolder,
				installationMode: tt.fields.installationMode,
				statusdNames:     tt.fields.statusdNames,
			}
			if got := dm.GetPackageType(); got != tt.want {
				t.Errorf("dpkgManager.GetPackageType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetPackageInfo(t *testing.T) {
	type fields struct {
		name    string
		version string
		errMsg  string
	}
	tests := []struct {
		name string
		file string
		want fields
	}{
		{
			name: "valid package file format",
			file: `Package: tzdata
			Version: 2021a-1+deb11u8
			Architecture: all
			Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
			Installed-Size: 3393
			Depends: debconf (>= 0.5) | debconf-2.0
			Provides: tzdata-bullseye
			Section: localization
			Priority: required
			Multi-Arch: foreign
			Homepage: https://www.iana.org/time-zones
			Description: time zone and daylight-saving time data
			 This package contains data required for the implementation of
			 standard local time for many representative locations around the
			 globe. It is updated periodically to reflect changes made by
			 political bodies to time zone boundaries, UTC offsets, and
			 daylight-saving rules.`,
			want: fields{
				name:    "tzdata",
				version: "2021a-1+deb11u8",
				errMsg:  "",
			},
		},
		{
			name: "invalid package file format",
			file: "PackageVersion",
			want: fields{
				name:    "",
				version: "",
				errMsg:  "no package name found for package",
			},
		},
		{
			name: "rejects leading dash (apt option injection)",
			file: "Package: -malicious\nVersion: 1.0",
			want: fields{
				name:    "",
				version: "",
				errMsg:  `invalid package name "-malicious"`,
			},
		},
		{
			name: "rejects double dash",
			file: "Package: --force-all\nVersion: 1.0",
			want: fields{
				name:    "",
				version: "",
				errMsg:  `invalid package name "--force-all"`,
			},
		},
		{
			name: "rejects whitespace in name",
			file: "Package: foo bar\nVersion: 1.0",
			want: fields{
				name:    "",
				version: "",
				errMsg:  `invalid package name "foo bar"`,
			},
		},
		{
			name: "accepts name with plus signs",
			file: "Package: g++\nVersion: 4:10.2.1",
			want: fields{
				name:    "g++",
				version: "4:10.2.1",
				errMsg:  "",
			},
		},
		{
			name: "accepts name with digits and dots",
			file: "Package: libssl1.1\nVersion: 1.1.1n-0+deb11u5",
			want: fields{
				name:    "libssl1.1",
				version: "1.1.1n-0+deb11u5",
				errMsg:  "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, err := GetPackageInfo(tt.file)
			var errMsg string
			if err == nil {
				errMsg = ""
			} else {
				errMsg = err.Error()
			}

			if name != tt.want.name || version != tt.want.version || errMsg != tt.want.errMsg {
				t.Errorf("GetPackageInfo() = Name: %v, Version: %v Error: %v, want Name: %v, Version: %v, Error: %v", name, version, err, tt.want.name, tt.want.version, tt.want.errMsg)
			}
		})
	}
}

func Test_installUpdates_DPKG(t *testing.T) {
	tests := []struct {
		name                  string
		updates               unversioned.UpdatePackages
		ignoreErrors          bool
		mockSetup             func(reference *mocks.MockReference)
		expectedResult        []byte
		expectNoUpdates       bool
		expectedErrorContains string
	}{
		{
			name: "Update all packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte(nil), nil)
			},
			ignoreErrors:   false,
			expectedResult: nil,
		},
		{
			name: "Update all packages missing updates marker",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.MatchedBy(func(req gwclient.ReadRequest) bool {
					return req.Filename == "/updates.txt"
				})).Return([]byte(nil), fmt.Errorf("failed to stat /updates.txt: no such file or directory"))
			},
			expectNoUpdates: true,
		},
		{
			name: "Update all packages unrelated marker read failure",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.MatchedBy(func(req gwclient.ReadRequest) bool {
					return req.Filename == "/updates.txt"
				})).Return([]byte(nil), fmt.Errorf("repository not found"))
			},
			expectedErrorContains: "failed while checking for available apt updates: repository not found",
		},
		{
			name: "Update specific packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1-1.0.1\npackage2-2.0.2\n"), nil)
			},
			updates: unversioned.UpdatePackages{
				{Name: "package1", FixedVersion: "1.0.1"},
				{Name: "package2", FixedVersion: "2.0.1"},
			},
			ignoreErrors:   false,
			expectedResult: []byte("package1-1.0.1\npackage2-2.0.2\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mocks.MockGWClient)
			mockRef := new(mocks.MockReference)

			mockResult := &gwclient.Result{}
			mockResult.SetRef(mockRef)

			mockClient.On("Solve", mock.Anything, mock.Anything).Return(mockResult, nil)

			if tt.mockSetup != nil {
				tt.mockSetup(mockRef)
			}

			dm := &dpkgManager{
				config: &buildkit.Config{
					Client:     mockClient,
					ImageState: llb.Scratch(),
				},
			}

			updatedState, resultBytes, err := dm.installUpdates(context.TODO(), tt.updates, tt.ignoreErrors)

			switch {
			case tt.expectNoUpdates:
				assert.ErrorIs(t, err, types.ErrNoUpdatesFound)
				assert.Nil(t, updatedState)
				assert.Nil(t, resultBytes)
			case tt.expectedErrorContains != "":
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), tt.expectedErrorContains)
				}
				assert.False(t, errors.Is(err, types.ErrNoUpdatesFound))
				assert.Nil(t, updatedState)
				assert.Nil(t, resultBytes)
			default:
				assert.NoError(t, err)
				assert.NotNil(t, updatedState)
				assert.Equal(t, tt.expectedResult, resultBytes)
			}

			mockClient.AssertExpectations(t)
			mockRef.AssertExpectations(t)
		})
	}
}

func writeDPKGTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	assert.NoError(t, os.WriteFile(path, contents, 0o600))
	assert.NoError(t, os.Chmod(path, mode))
}
