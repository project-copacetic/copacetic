package chisel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	nativeTargetedPatchError = "targeted patching of native Chisel manifests is not supported; omit --report to run a comprehensive Chisel update"
	binfmtImage              = "docker.io/tonistiigi/binfmt:qemu-v10.2.3@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
)

func TestRealImageFixturesAreDigestPinned(t *testing.T) {
	var fixtures []realImageFixture
	require.NoError(t, json.Unmarshal(fixtureData, &fixtures))
	require.NotEmpty(t, fixtures)
	for _, fixture := range fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			assertDigestPinnedReference(t, fixture.Reference)
			require.NotEmpty(t, fixture.Platform)
		})
	}
	assertDigestPinnedReference(t, chiselToolingImage)
	assertDigestPinnedReference(t, binfmtImage)
}

func assertDigestPinnedReference(t *testing.T, reference string) {
	t.Helper()
	_, digest, found := strings.Cut(reference, "@sha256:")
	require.True(t, found, "image reference is not digest-pinned: %s", reference)
	require.Len(t, digest, 64, "image reference has an invalid sha256 digest: %s", reference)
	_, err := hex.DecodeString(digest)
	require.NoError(t, err, "image reference has an invalid sha256 digest: %s", reference)
	require.Equal(t, strings.ToLower(digest), digest, "image digest must use lowercase hexadecimal: %s", reference)
}

func TestUnresolvableSliceMutationProducesValidManifest(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "integration", "chisel", "fixtures", "manifest-schema-1.0", "manifest.wall")
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	mutated := addUnresolvableSlice(t, data, "copa-private-package", "amd64")
	manifest, err := copachisel.ParseManifest(bytes.NewReader(mutated))
	require.NoError(t, err)
	require.Contains(t, manifest.Packages, "copa-private-package")
	require.Contains(t, manifest.Slices, "copa-private-package_bins")
}

func TestNativeChiselRealImageARM64(t *testing.T) {
	testNativeChiselRealImage(t, "canonical-native-dotnet-arm64")
}

func testNativeChiselRealImage(t *testing.T, fixtureID string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	fixture := loadFixture(t, fixtureID)
	if fixture.Platform == platformLinuxARM64 {
		ensureArm64Execution(t)
	}
	requireLocalImage(t, chiselToolingImage)

	pullImage(t, fixture.Reference, fixture.Platform)
	before := captureImage(t, fixture.Reference, fixture.Platform)
	require.NotNil(t, before.Manifest)
	require.Empty(t, before.DPKGStatus)
	assertForbiddenToolingAbsent(t, &before)
	assertManifestMatchesRootFSTar(t, before.Manifest, before.RootFSTar)

	beforeRuntime := runDocker(t, fixture.Platform, fixture.Reference, "--info")
	require.Contains(t, beforeRuntime, fixture.RuntimeContains)

	patched := uniqueImage("native-" + strings.ReplaceAll(fixture.Platform, "/", "-"))
	t.Cleanup(func() { removeImage(patched) })
	patchImage(t,
		"patch",
		"--image", fixture.Reference,
		"--tag", patched,
		"--platform", fixture.Platform,
	)

	after := captureImage(t, patched, fixture.Platform)
	require.NotNil(t, after.Manifest)
	require.Empty(t, after.DPKGStatus)
	assertImageConfigPreserved(t, &before.Config, &after.Config)
	assertForbiddenToolingAbsent(t, &after)
	assertManifestUpgrade(t, before.Manifest, after.Manifest, fixture.ExpectedUpgradePackages)
	assertManifestMatchesRootFSTar(t, after.Manifest, after.RootFSTar)
	assert.Equal(t, "ubuntu-24.04", after.Config.Config.Labels["sh.copa.chisel.release"])
	assert.Equal(t, "v1.4.2", after.Config.Config.Labels["sh.copa.chisel.version"])

	afterRuntime := runDocker(t, fixture.Platform, patched, "--info")
	require.Contains(t, afterRuntime, fixture.RuntimeContains)
	require.NotEqual(t, beforeRuntime, afterRuntime, "expected the .NET runtime version to change")

	assertNoUpdates(t,
		"patch",
		"--image", patched,
		"--tag", uniqueImage("native-repatch"),
		"--platform", fixture.Platform,
	)
}

func TestNativeChiselMultiPlatformOCIUpdatesAMD64AndARM64(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	ensureArm64Execution(t)
	requireLocalImage(t, chiselToolingImage)

	indexFixture := loadFixture(t, "canonical-native-index")
	fixtures := []realImageFixture{
		loadFixture(t, "canonical-native-dotnet"),
		loadFixture(t, "canonical-native-dotnet-arm64"),
	}
	before := make(map[string]imageSnapshot, len(fixtures))
	for _, fixture := range fixtures {
		pullImage(t, fixture.Reference, fixture.Platform)
		before[fixture.Platform] = captureImage(t, fixture.Reference, fixture.Platform)
	}

	outputDir := filepath.Join(t.TempDir(), "oci")
	outputTag := uniqueImage("native-multiplatform")
	cleanupImageTags(t, outputTag, platformLinuxAMD64, platformLinuxARM64)
	patchImage(t,
		"patch",
		"--image", indexFixture.Reference,
		"--tag", outputTag,
		"--platform", strings.Join([]string{platformLinuxAMD64, platformLinuxARM64}, ","),
		"--chisel-release", indexFixture.ChiselRelease,
		"--oci-dir", outputDir,
	)

	outputIndex := readOCIIndex(t, filepath.Join(outputDir, "index.json"))
	sourceData := []byte(run(t, "docker", "buildx", "imagetools", "inspect", "--raw", indexFixture.Reference))
	var sourceIndex ociIndex
	require.NoError(t, json.Unmarshal(sourceData, &sourceIndex))
	outputDescriptors := descriptorsByPlatform(outputIndex)
	sourceDescriptors := descriptorsByPlatform(sourceIndex)

	for _, fixture := range fixtures {
		t.Run(strings.ReplaceAll(fixture.Platform, "/", "-"), func(t *testing.T) {
			sourceDescriptor, ok := sourceDescriptors[fixture.Platform]
			require.True(t, ok, "source index is missing %s", fixture.Platform)
			outputDescriptor, ok := outputDescriptors[fixture.Platform]
			require.True(t, ok, "patched index is missing %s", fixture.Platform)
			require.NotEqual(t, sourceDescriptor.Digest, outputDescriptor.Digest, "%s descriptor was preserved instead of patched", fixture.Platform)

			after := captureOCIImage(t, outputDir, outputDescriptor)
			baseline := before[fixture.Platform]
			require.NotNil(t, baseline.Manifest)
			assertImageConfigPreserved(t, &baseline.Config, &after.Config)
			assertManifestUpgrade(t, baseline.Manifest, after.Manifest, fixture.ExpectedUpgradePackages)
			assertManifestMatchesRootFSView(t, after.Manifest, after.RootFS)
			assert.Equal(t, "ubuntu-24.04", after.Config.Config.Labels["sh.copa.chisel.release"])
			assert.Equal(t, "v1.4.2", after.Config.Config.Labels["sh.copa.chisel.version"])
			assert.Equal(t, "ubuntu-24.04", after.Annotations["sh.copa.chisel.release"])
			assert.Equal(t, "v1.4.2", after.Annotations["sh.copa.chisel.version"])
		})
	}
}

func TestNativeChiselSecondaryArchitecturesOCI(t *testing.T) {
	requireSecondaryArchitectureTests(t)
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireLocalImage(t, chiselToolingImage)

	indexFixture := loadFixture(t, "canonical-native-index")
	fixtures := []realImageFixture{
		loadFixture(t, "canonical-native-dotnet-ppc64le"),
		loadFixture(t, "canonical-native-dotnet-s390x"),
	}
	before := make(map[string]imageSnapshot, len(fixtures))
	for _, fixture := range fixtures {
		ensurePlatformExecution(t, fixture.Platform, configuredBinfmtArchitecture(fixture.Platform))
		pullImage(t, fixture.Reference, fixture.Platform)
		before[fixture.Platform] = captureImage(t, fixture.Reference, fixture.Platform)
	}

	outputDir := filepath.Join(t.TempDir(), "oci")
	outputTag := uniqueImage("native-secondary-platforms")
	cleanupImageTags(t, outputTag, "linux/ppc64le", "linux/s390x")
	patchImage(t,
		"patch",
		"--image", indexFixture.Reference,
		"--tag", outputTag,
		"--platform", "linux/ppc64le,linux/s390x",
		"--chisel-release", indexFixture.ChiselRelease,
		"--oci-dir", outputDir,
	)

	outputIndex := readOCIIndex(t, filepath.Join(outputDir, "index.json"))
	sourceData := []byte(run(t, "docker", "buildx", "imagetools", "inspect", "--raw", indexFixture.Reference))
	var sourceIndex ociIndex
	require.NoError(t, json.Unmarshal(sourceData, &sourceIndex))
	outputDescriptors := descriptorsByPlatform(outputIndex)
	sourceDescriptors := descriptorsByPlatform(sourceIndex)

	for _, fixture := range fixtures {
		t.Run(strings.ReplaceAll(fixture.Platform, "/", "-"), func(t *testing.T) {
			sourceDescriptor := sourceDescriptors[fixture.Platform]
			outputDescriptor := outputDescriptors[fixture.Platform]
			require.NotEmpty(t, sourceDescriptor.Digest)
			require.NotEmpty(t, outputDescriptor.Digest)
			require.NotEqual(t, sourceDescriptor.Digest, outputDescriptor.Digest)
			after := captureOCIImage(t, outputDir, outputDescriptor)
			baseline := before[fixture.Platform]
			assertImageConfigPreserved(t, &baseline.Config, &after.Config)
			assertManifestUpgrade(t, baseline.Manifest, after.Manifest, fixture.ExpectedUpgradePackages)
			assertManifestMatchesRootFSView(t, after.Manifest, after.RootFS)
			assert.Equal(t, indexFixture.ChiselRelease, after.Config.Config.Labels["sh.copa.chisel.release"])
			assert.Equal(t, "v1.4.2", after.Config.Config.Labels["sh.copa.chisel.version"])
			assert.Equal(t, indexFixture.ChiselRelease, after.Annotations["sh.copa.chisel.release"])
			assert.Equal(t, "v1.4.2", after.Annotations["sh.copa.chisel.version"])
		})
	}
}

func TestAptlessFullStatusComprehensiveFromBaselineARM64(t *testing.T) {
	testAptlessFullStatusComprehensiveFromBaseline(t, "microsoft-full-status-dotnet-arm64", "arm64")
}

func TestAptlessFullStatusComprehensiveFromBaselineARMv7(t *testing.T) {
	requireSecondaryArchitectureTests(t)
	testAptlessFullStatusComprehensiveFromBaseline(t, "microsoft-full-status-dotnet-arm-v7", "arm")
}

func testAptlessFullStatusComprehensiveFromBaseline(t *testing.T, fixtureID, binfmtArchitecture string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	fixture := loadFixture(t, fixtureID)
	ensurePlatformExecution(t, fixture.Platform, binfmtArchitecture)

	pullImage(t, fixture.Reference, fixture.Platform)
	before := captureImage(t, fixture.Reference, fixture.Platform)
	assertFullStatusLayout(t, &before)
	beforePackages := parseDPKGStatus(t, before.DPKGStatus)
	beforeRuntime := runDocker(t, fixture.Platform, fixture.Reference, "--info")

	patched := uniqueImage("full-status-comprehensive-arm64")
	t.Cleanup(func() { removeImage(patched) })
	patchImage(t,
		"patch",
		"--image", fixture.Reference,
		"--tag", patched,
		"--platform", fixture.Platform,
	)

	after := captureImage(t, patched, fixture.Platform)
	assertFullStatusLayout(t, &after)
	assertImageConfigPreserved(t, &before.Config, &after.Config)
	afterPackages := parseDPKGStatus(t, after.DPKGStatus)
	assertNoDPKGDowngrades(t, beforePackages, afterPackages)
	for _, name := range fixture.ExpectedUpgradePackages {
		requireVersionGreater(t, afterPackages[name].Version, beforePackages[name].Version, name)
	}
	afterRuntime := runDocker(t, fixture.Platform, patched, "--info")
	assert.Equal(t, beforeRuntime, afterRuntime, "comprehensive OS patching must not replace the separately copied .NET runtime")
	assertNoUpdates(t,
		"patch",
		"--image", patched,
		"--tag", uniqueImage("full-status-comprehensive-arm64-repatch"),
		"--platform", fixture.Platform,
	)
}

func TestNativeChiselRejectsTargetedReportBeforeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")

	fixture := loadFixture(t, "canonical-native-dotnet")
	reportPath := filepath.Join(t.TempDir(), "report.json")
	writeSyntheticTrivyReport(t, reportPath, "amd64", "libc6")
	outputDir := filepath.Join(t.TempDir(), "must-not-exist")
	outputTag := uniqueImage("native-report-rejected")
	t.Cleanup(func() { removeImage(outputTag) })

	output, err := patchImageExpectError(t,
		"patch",
		"--image", fixture.Reference,
		"--report", reportPath,
		"--tag", outputTag,
		"--platform", fixture.Platform,
		"--oci-dir", outputDir,
	)
	require.Error(t, err)
	require.Contains(t, output, nativeTargetedPatchError)
	assertNoPatchOutput(t, outputTag, outputDir)
}

func TestNativeChiselRejectsARMv6BeforeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")

	fixture := loadFixture(t, "canonical-native-dotnet")
	target := buildImageFromDockerfile(t, "native-arm-v6", "linux/arm/v6", fmt.Sprintf(`
FROM --platform=linux/amd64 %s AS source
FROM scratch
COPY --from=source / /
`, fixture.Reference), nil)
	outputTag := uniqueImage("native-arm-v6-rejected")
	outputDir := filepath.Join(t.TempDir(), "must-not-exist")
	t.Cleanup(func() { removeImage(outputTag) })

	output, err := patchImageExpectError(t,
		"patch",
		"--image", target,
		"--tag", outputTag,
		"--platform", "linux/arm/v6",
		"--oci-dir", outputDir,
	)
	require.Error(t, err)
	require.Contains(t, output, "unsupported Chisel platform linux/arm/v6")
	assertNoPatchOutput(t, outputTag, outputDir)
}

func TestNativeChiselUnresolvablePrivatePackageFailsBeforeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireLocalImage(t, chiselToolingImage)

	fixture := loadFixture(t, "canonical-native-dotnet")
	pullImage(t, fixture.Reference, fixture.Platform)
	baseline := captureImage(t, fixture.Reference, fixture.Platform)
	const packageName = "copa-private-package"
	mutatedManifest := addUnresolvableSlice(t, baseline.ManifestData, packageName, "amd64")
	target := buildImageFromDockerfile(t, "native-private-package", fixture.Platform, fmt.Sprintf(`
FROM %s AS source
FROM scratch
COPY --from=source / /
COPY manifest.wall /var/lib/chisel/manifest.wall
`, fixture.Reference), map[string][]byte{"manifest.wall": mutatedManifest})
	outputTag := uniqueImage("native-private-package-rejected")
	outputDir := filepath.Join(t.TempDir(), "must-not-exist")
	t.Cleanup(func() { removeImage(outputTag) })

	output, err := patchImageExpectError(t,
		"patch",
		"--image", target,
		"--tag", outputTag,
		"--platform", fixture.Platform,
		"--oci-dir", outputDir,
	)
	require.Error(t, err)
	require.Contains(t, output, packageName, "failure must identify the unresolved public-release package")
	assertNoPatchOutput(t, outputTag, outputDir)
}

func TestDistrolessStatusDirectoryPreservesEncodedFilenames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireLocalImage(t, chiselToolingImage)

	fixture := loadFixture(t, "distroless-status-directory")
	sentinel := []byte("unmanaged application sentinel\n")
	target := buildImageFromDockerfile(t, "status-directory", fixture.Platform, fmt.Sprintf(`
FROM %s AS source
FROM %s AS prepare
COPY --from=source / /rootfs
RUN mv "/rootfs/var/lib/dpkg/status.d/%s" "/rootfs/var/lib/dpkg/status.d/%s"
COPY sentinel.txt /rootfs/%ssentinel.txt
FROM scratch
COPY --from=prepare /rootfs /
`, fixture.Reference, chiselToolingImage, fixture.EncodedStatusPackage, fixture.EncodedStatusFilename, fixture.PreserveTree), map[string][]byte{
		"sentinel.txt": sentinel,
	})

	before := captureImage(t, target, fixture.Platform)
	assertStatusDirectoryLayout(t, &before)
	beforePackages, beforeFilenames := parseStatusDirectory(t, before.StatusDirectory)
	require.Equal(t, fixture.EncodedStatusFilename, beforeFilenames[fixture.EncodedStatusPackage])
	beforeSentinelHash := canonicalTreeHash(t, before.RootFSTar, fixture.PreserveTree)

	reportPath := filepath.Join(t.TempDir(), "report.json")
	writeSyntheticOSPackageReport(t, reportPath, "debian", "12", "amd64", "libssl3", "3.0.11-1~deb12u2", "3.0.11-1~deb12u3")

	patched := uniqueImage("status-directory-patched")
	t.Cleanup(func() { removeImage(patched) })
	patchImage(t,
		"patch",
		"--image", target,
		"--report", reportPath,
		"--tag", patched,
		"--platform", fixture.Platform,
	)

	after := captureImage(t, patched, fixture.Platform)
	assertStatusDirectoryLayout(t, &after)
	assertImageConfigPreserved(t, &before.Config, &after.Config)
	afterPackages, afterFilenames := parseStatusDirectory(t, after.StatusDirectory)
	assertNoDPKGDowngrades(t, beforePackages, afterPackages)
	for packageName, filename := range beforeFilenames {
		require.Equal(t, filename, afterFilenames[packageName], "status.d filename changed for package %s", packageName)
	}
	require.Equal(t, fixture.EncodedStatusFilename, afterFilenames[fixture.EncodedStatusPackage])
	for _, name := range fixture.ExpectedUpgradePackages {
		requireVersionGreater(t, afterPackages[name].Version, beforePackages[name].Version, name)
	}
	require.Equal(t, beforeSentinelHash, canonicalTreeHash(t, after.RootFSTar, fixture.PreserveTree), "unmanaged application content changed")
}

func ensureArm64Execution(t *testing.T) {
	t.Helper()
	ensurePlatformExecution(t, "linux/arm64", "arm64")
}

func ensurePlatformExecution(t *testing.T, platform, binfmtArchitecture string) {
	t.Helper()
	command := func() ([]byte, error) {
		cmd := exec.Command("docker", "run", "--rm", "--platform", platform, chiselToolingImage, "version")
		cmd.Env = os.Environ()
		return cmd.CombinedOutput()
	}
	if output, err := command(); err == nil && strings.TrimSpace(string(output)) == "v1.4.2" {
		return
	}
	installBinfmt(t, binfmtArchitecture)
	output, err := command()
	require.NoError(t, err, "%s execution is unavailable after installing pinned binfmt support:\n%s", platform, string(output))
	require.Equal(t, "v1.4.2", strings.TrimSpace(string(output)))
}

func requireSecondaryArchitectureTests(t *testing.T) {
	t.Helper()
	if os.Getenv("COPA_CHISEL_SECONDARY_ARCHES") != "1" {
		t.Skip("set COPA_CHISEL_SECONDARY_ARCHES=1 to run ppc64le, s390x, and arm/v7 patch validation")
	}
}

func configuredBinfmtArchitecture(platform string) string {
	switch platform {
	case "linux/ppc64le":
		return "ppc64le"
	case "linux/s390x":
		return "s390x"
	case "linux/arm/v7":
		return "arm"
	case "linux/arm64":
		return "arm64"
	default:
		return platform
	}
}

func installBinfmt(t *testing.T, architecture string) {
	t.Helper()
	output, err := exec.Command(
		"docker", "run", "--privileged", "--rm",
		binfmtImage, "--install", architecture,
	).CombinedOutput()
	require.NoError(t, err, "install %s binfmt support with pinned helper image:\n%s", architecture, string(output))
}

func requireVersionAtLeastOneFixedVersion(t *testing.T, actual, fixedVersions, packageName, vulnerabilityID string) {
	t.Helper()
	var candidates []string
	for _, candidate := range strings.Split(fixedVersions, ",") {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			candidates = append(candidates, candidate)
			if compareDebianVersions(t, actual, candidate) >= 0 {
				return
			}
		}
	}
	t.Fatalf("package %s is version %s after patching, below every fixed version %v for %s", packageName, actual, candidates, vulnerabilityID)
}

func readOCIIndex(t *testing.T, filename string) ociIndex {
	t.Helper()
	data, err := os.ReadFile(filename)
	require.NoError(t, err)
	var index ociIndex
	require.NoError(t, json.Unmarshal(data, &index))
	return index
}

func writeSyntheticTrivyReport(t *testing.T, filename, architecture, packageName string) {
	t.Helper()
	writeSyntheticOSPackageReport(t, filename, "ubuntu", "24.04", architecture, packageName, "0", "9999")
}

func writeSyntheticOSPackageReport(t *testing.T, filename, osFamily, osVersion, architecture, packageName, installedVersion, fixedVersion string) {
	t.Helper()
	report := map[string]any{
		"SchemaVersion": 2,
		"Metadata": map[string]any{
			"OS":          map[string]any{"Family": osFamily, "Name": osVersion},
			"ImageConfig": map[string]any{"architecture": architecture},
		},
		"Results": []any{map[string]any{
			"Target": osFamily + " " + osVersion,
			"Class":  "os-pkgs",
			"Type":   osFamily,
			"Vulnerabilities": []any{map[string]any{
				"VulnerabilityID":  "CVE-2099-COPA-E2E",
				"PkgName":          packageName,
				"InstalledVersion": installedVersion,
				"FixedVersion":     fixedVersion,
			}},
		}},
	}
	data, err := json.Marshal(report)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filename, data, 0o600))
}

func patchImageExpectError(t *testing.T, args ...string) (string, error) {
	t.Helper()
	args = append(args, "--loader", "docker", "--progress", "plain", "--timeout", chiselPatchTimeout())
	if buildkitAddr != "" {
		args = append(args, "--addr", buildkitAddr)
	}
	cmd := exec.Command(copaPath, args...) // #nosec G204 -- test inputs are fixed fixtures and generated local tags.
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func assertNoPatchOutput(t *testing.T, image, ociDir string) {
	t.Helper()
	for _, candidate := range []string{image, image + "-amd64", image + "-arm64", image + "-arm-v6"} {
		assertDockerImageAbsent(t, candidate, "failed patch")
	}
	_, err := os.Stat(ociDir)
	require.ErrorIs(t, err, os.ErrNotExist, "failed patch unexpectedly created OCI output at %s", ociDir)
}

func buildImageFromDockerfile(t *testing.T, prefix, platform, dockerfile string, files map[string][]byte) string {
	t.Helper()
	contextDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(contextDir, "Dockerfile"), []byte(strings.TrimSpace(dockerfile)+"\n"), 0o600))
	for name, data := range files {
		filename := filepath.Join(contextDir, filepath.Clean(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0o755))
		require.NoError(t, os.WriteFile(filename, data, 0o600))
	}
	image := uniqueImage(prefix)
	t.Cleanup(func() { removeImage(image) })
	run(t,
		"docker", "buildx", "build",
		"--load",
		"--provenance=false",
		"--platform", platform,
		"--tag", image,
		contextDir,
	)
	return image
}

func addUnresolvableSlice(t *testing.T, compressed []byte, packageName, architecture string) []byte {
	t.Helper()
	packageRecord := struct {
		Kind    string `json:"kind"`
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
		Arch    string `json:"arch"`
	}{"package", packageName, "1.0", strings.Repeat("0", 64), architecture}
	sliceRecord := struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}{"slice", packageName + "_bins"}
	return addManifestRecords(t, compressed, packageRecord, sliceRecord)
}

func addManifestRecords(t *testing.T, compressed []byte, extraRecords ...any) []byte {
	t.Helper()
	decoder, err := zstd.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(decoder)
	decoder.Close()
	require.NoError(t, err)

	lines := bytes.Split(bytes.TrimSpace(decompressed), []byte{'\n'})
	require.NotEmpty(t, lines)
	var header map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &header))
	records := make([]string, 0, len(lines)-1+len(extraRecords))
	for _, line := range lines[1:] {
		records = append(records, string(line))
	}
	for _, record := range extraRecords {
		data, err := json.Marshal(record)
		require.NoError(t, err)
		records = append(records, string(data))
	}
	sort.Strings(records)
	header["count"] = len(records) + 1
	headerData, err := json.Marshal(header)
	require.NoError(t, err)

	var output bytes.Buffer
	output.Write(headerData)
	output.WriteByte('\n')
	for _, record := range records {
		output.WriteString(record)
		output.WriteByte('\n')
	}

	var result bytes.Buffer
	encoder, err := zstd.NewWriter(&result, zstd.WithEncoderConcurrency(1))
	require.NoError(t, err)
	_, err = encoder.Write(output.Bytes())
	require.NoError(t, err)
	require.NoError(t, encoder.Close())
	return result.Bytes()
}

func assertStatusDirectoryLayout(t *testing.T, snapshot *imageSnapshot) {
	t.Helper()
	require.Empty(t, snapshot.DPKGStatus, "/var/lib/dpkg/status must remain absent")
	require.Nil(t, snapshot.Manifest)
	// Docker exports every status file but may omit an explicit tar header for
	// its parent directory. The populated status-directory view is authoritative.
	require.NotEmpty(t, snapshot.StatusDirectory)
	assertForbiddenToolingAbsent(t, snapshot)
}

func parseStatusDirectory(t *testing.T, files map[string][]byte) (map[string]statusPackage, map[string]string) {
	t.Helper()
	packages := make(map[string]statusPackage)
	filenames := make(map[string]string)
	for filename, data := range files {
		if strings.HasSuffix(filename, ".md5sums") {
			continue
		}
		parsed := parseDPKGStatus(t, data)
		require.Len(t, parsed, 1, "status.d file %s must contain exactly one package paragraph", filename)
		for packageName, status := range parsed {
			_, duplicate := packages[packageName]
			require.False(t, duplicate, "package %s appears in more than one status.d file", packageName)
			packages[packageName] = status
			filenames[packageName] = filename
		}
	}
	return packages, filenames
}
