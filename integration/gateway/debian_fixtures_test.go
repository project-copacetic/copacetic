package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	debversion "github.com/knqyf263/go-deb-version"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/test/testenv"
)

const (
	debianFixtureImage = "gcr.io/distroless/base-debian12@" +
		"sha256:5eae9ef0b97acf7de819f936e12b24976b2d54333a2cf329615366e16ba598cd"
	debianFixturePython = "docker.io/library/python:3.11.6-bookworm@" +
		"sha256:ba7a7ac30c38e119c4304f98ef0e188f90f4f67a958bb6899da9defb99bfb471"
	debianFixtureNginx = "docker.io/library/nginx:1.25.3-bookworm@" +
		"sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2"
	debianStatusDir         = "/var/lib/dpkg/status.d/"
	debianStatusDB          = "/var/lib/dpkg/status"
	opensslConfigPath       = "/etc/ssl/openssl.cnf"
	debianDebconfConfigPath = "/etc/debconf.conf"
	debianDebconfCachePath  = "/var/cache/debconf"
)

type debianFixturePackage struct {
	name, filename, fixedVersion string
}

// Generate the custom layouts from supported, immutable Debian bases so these
// checks do not depend on a separately published image with expired repositories.
func TestDebianCustomStatusDirectories(t *testing.T) {
	if buildkitAddr == "" {
		t.Skip("a BuildKit address is required")
	}
	tests := []struct {
		name          string
		packages      []debianFixturePackage
		customOpenSSL bool
	}{
		{
			name:     "dotted filename",
			packages: []debianFixturePackage{{"libssl3", "libssl3.0", "3.0.11-1~deb12u3"}},
		},
		{
			name: "overlapping filenames",
			packages: []debianFixturePackage{
				{"libssl3", "libssl3.0", "3.0.11-1~deb12u3"},
				{"libc6", "libssl3", "2.36-9+deb12u7"},
			},
		},
		{
			name:          "modified OpenSSL conffile",
			packages:      []debianFixturePackage{{"openssl", "openssl", "3.0.11-1~deb12u3"}},
			customOpenSSL: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, mode := range []string{"report", "no report"} {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
					defer cancel()
					testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, client gwclient.Client) {
						platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
						cfg, err := buildkit.InitializeBuildkitConfig(ctx, client, debianFixtureImage, platform)
						require.NoError(t, err)
						state := cfg.ImageState
						if tc.customOpenSSL {
							// Copy an installed, package-owned binary and its complete status
							// record, including the original conffile checksum.
							source := llb.Image(debianFixturePython, llb.Platform(*platform)).Run(
								llb.Args([]string{"sh", "-ec", "dpkg-query -s openssl > /openssl.status"}),
							).Root()
							state = state.File(llb.Copy(source, "/openssl.status", debianStatusDir+"openssl")).
								File(llb.Copy(source, "/usr/bin/openssl", "/usr/bin/openssl", &llb.CopyInfo{CreateDestPath: true})).
								File(llb.Mkfile(opensslConfigPath, 0o644, []byte("foo\n"))).
								File(llb.Copy(source, debianDebconfConfigPath, debianDebconfConfigPath)).
								File(llb.Copy(source, debianDebconfCachePath, debianDebconfCachePath, &llb.CopyInfo{CreateDestPath: true}))
						} else {
							// Remove originals before copying from the unchanged source,
							// since one destination may be another package's original name.
							for _, pkg := range tc.packages {
								state = state.File(llb.Rm(debianStatusDir + pkg.name)).
									File(llb.Rm(debianStatusDir + pkg.name + ".md5sums"))
							}
							for _, pkg := range tc.packages {
								state = state.File(llb.Copy(cfg.ImageState, debianStatusDir+pkg.name, debianStatusDir+pkg.filename)).
									File(llb.Copy(cfg.ImageState, debianStatusDir+pkg.name+".md5sums", debianStatusDir+pkg.filename+".md5sums"))
							}
						}
						cfg.ImageState = state
						before := solveDebianFixture(t, ctx, client, &state)
						updates := make([]testenv.PackageUpdate, 0, len(tc.packages))
						for _, pkg := range tc.packages {
							record := readDebianFixtureFile(t, ctx, before, debianStatusDir+pkg.filename)
							require.Equal(t, pkg.name, debianFixtureStatusField(record, "Package"))
							updates = append(updates, testenv.PackageUpdate{
								Name:             pkg.name,
								InstalledVersion: debianFixtureStatusField(record, "Version"),
								FixedVersion:     pkg.fixedVersion,
							})
							if tc.customOpenSSL {
								require.Contains(t, record, " "+opensslConfigPath+" ", "the package must own the modified conffile")
							}
						}
						var manifest *unversioned.UpdateManifest
						if mode == "report" {
							manifest = testenv.CreateUpdateManifest("debian", "12", "amd64", updates)
						}
						manager, err := pkgmgr.GetPackageManager("debian", "12", cfg, t.TempDir())
						require.NoError(t, err)
						patched, failed, err := manager.InstallUpdates(ctx, manifest, false)
						require.NoError(t, err)
						require.Empty(t, failed)
						require.NotNil(t, patched)
						after := solveDebianFixture(t, ctx, client, patched)
						for i, pkg := range tc.packages {
							record := readDebianFixtureFile(t, ctx, after, debianStatusDir+pkg.filename)
							require.Equal(t, pkg.name, debianFixtureStatusField(record, "Package"), "preserve the exact package-to-filename mapping")
							assertDebianFixtureUpgrade(t, updates[i].InstalledVersion, debianFixtureStatusField(record, "Version"), pkg.fixedVersion)
						}
						absentPaths := []string{debianStatusDB, "/usr/bin/apt-get"}
						if !tc.customOpenSSL {
							absentPaths = append(absentPaths, debianDebconfConfigPath, debianDebconfCachePath)
						}
						for _, absent := range absentPaths {
							_, err := after.StatFile(ctx, gwclient.StatRequest{Path: absent})
							require.ErrorContains(t, err, "no such file or directory", "%s must remain absent", absent)
						}
						if tc.customOpenSSL {
							require.Equal(t, "foo\n", readDebianFixtureFile(t, ctx, after, opensslConfigPath))
							// The temporary Debconf used by the tooling must not modify
							// configuration or database files supplied by the image.
							for _, path := range []string{debianDebconfConfigPath, debianDebconfCachePath + "/config.dat"} {
								require.Equal(t, readDebianFixtureFile(t, ctx, before, path), readDebianFixtureFile(t, ctx, after, path))
							}
						}
					}, testenv.WithSkipExport())
				})
			}
		})
	}
}

func TestDebianCustomNetworkConfiguration(t *testing.T) {
	if buildkitAddr == "" {
		t.Skip("a BuildKit address is required")
	}
	t.Parallel()
	for _, mode := range []string{"report", "no report"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
			defer cancel()
			testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, client gwclient.Client) {
				cfg, err := buildkit.InitializeBuildkitConfig(ctx, client, debianFixtureNginx, &specs.Platform{OS: "linux", Architecture: "amd64"})
				require.NoError(t, err)
				const resolver = "# custom image resolver\nnameserver 192.0.2.1\noptions ndots:5\n"
				cfg.ImageState = cfg.ImageState.File(llb.Mkfile("/etc/resolv.conf", 0o644, []byte(resolver)))
				var manifest *unversioned.UpdateManifest
				if mode == "report" {
					manifest = testenv.CreateUpdateManifest("debian", "12", "amd64", []testenv.PackageUpdate{{
						Name: "bsdutils", InstalledVersion: "1:2.38.1-5+b1", FixedVersion: "1:2.38.1-5+deb12u1",
					}})
				}
				manager, err := pkgmgr.GetPackageManager("debian", "12", cfg, t.TempDir())
				require.NoError(t, err)
				patched, failed, err := manager.InstallUpdates(ctx, manifest, false)
				require.NoError(t, err)
				require.Empty(t, failed)
				require.NotNil(t, patched)
				after := solveDebianFixture(t, ctx, client, patched)
				require.Equal(t, resolver, readDebianFixtureFile(t, ctx, after, "/etc/resolv.conf"))
				status := readDebianFixtureFile(t, ctx, after, debianStatusDB)
				var version string
				for _, record := range strings.Split(status, "\n\n") {
					if debianFixtureStatusField(record, "Package") == "bsdutils" {
						version = debianFixtureStatusField(record, "Version")
						break
					}
				}
				assertDebianFixtureUpgrade(t, "1:2.38.1-5+b1", version, "1:2.38.1-5+deb12u1")
			}, testenv.WithSkipExport())
		})
	}
}

func solveDebianFixture(t *testing.T, ctx context.Context, client gwclient.Client, state *llb.State) gwclient.Reference {
	t.Helper()
	definition, err := state.Marshal(ctx)
	require.NoError(t, err)
	result, err := client.Solve(ctx, gwclient.SolveRequest{Definition: definition.ToPB(), Evaluate: true})
	require.NoError(t, err)
	ref, err := result.SingleRef()
	require.NoError(t, err)
	require.NotNil(t, ref)
	return ref
}

func readDebianFixtureFile(t *testing.T, ctx context.Context, ref gwclient.Reference, path string) string {
	t.Helper()
	data, err := ref.ReadFile(ctx, gwclient.ReadRequest{Filename: path})
	require.NoError(t, err)
	return string(data)
}

func debianFixtureStatusField(record, field string) string {
	for _, line := range strings.Split(record, "\n") {
		if value, ok := strings.CutPrefix(line, field+": "); ok {
			return value
		}
	}
	return ""
}

func assertDebianFixtureUpgrade(t *testing.T, before, after, minimum string) {
	t.Helper()
	oldVersion, err := debversion.NewVersion(before)
	require.NoError(t, err)
	newVersion, err := debversion.NewVersion(after)
	require.NoError(t, err)
	fixedVersion, err := debversion.NewVersion(minimum)
	require.NoError(t, err)
	require.True(t, newVersion.GreaterThan(oldVersion), "package must really upgrade: %s -> %s", before, after)
	require.False(t, newVersion.LessThan(fixedVersion), "installed %s is older than required %s", after, minimum)
}
