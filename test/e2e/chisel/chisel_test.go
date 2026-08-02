package chisel

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	debversion "github.com/knqyf263/go-deb-version"
	integrationcommon "github.com/project-copacetic/copacetic/integration/common"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var fixtureData []byte

const chiselToolingImage = "ghcr.io/project-copacetic/copacetic/chisel@sha256:587015954e14bf51aea440e69c8bf30bd010abd57ed8dd42c19e2159577e8c80"

type realImageFixture struct {
	ID                      string   `json:"id"`
	Layout                  string   `json:"layout"`
	Reference               string   `json:"reference"`
	Platform                string   `json:"platform"`
	ChiselRelease           string   `json:"chiselRelease"`
	ExpectedUpgradePackages []string `json:"expectedUpgradePackages"`
	RuntimeContains         string   `json:"runtimeContains"`
	PreserveTree            string   `json:"preserveTree"`
}

type imageSnapshot struct {
	Config       imageConfig
	Paths        map[string]pathMetadata
	Manifest     *copachisel.Manifest
	ManifestData []byte
	DPKGStatus   []byte
	RootFSTar    string
}

type imageConfig struct {
	Architecture string `json:"Architecture"`
	OS           string `json:"Os"`
	Config       struct {
		User         string                 `json:"User"`
		Entrypoint   []string               `json:"Entrypoint"`
		Cmd          []string               `json:"Cmd"`
		Env          []string               `json:"Env"`
		WorkingDir   string                 `json:"WorkingDir"`
		Labels       map[string]string      `json:"Labels"`
		Healthcheck  map[string]interface{} `json:"Healthcheck"`
		ExposedPorts map[string]interface{} `json:"ExposedPorts"`
		Volumes      map[string]interface{} `json:"Volumes"`
		StopSignal   string                 `json:"StopSignal"`
	} `json:"Config"`
}

type pathMetadata struct {
	Type     byte
	Mode     int64
	UID      int
	GID      int
	Size     int64
	Linkname string
}

type statusPackage struct {
	Version      string
	Architecture string
}

type trivyVulnerability struct {
	ID               string `json:"VulnerabilityID"`
	Package          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
}

type trivyReport struct {
	Metadata struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
}

type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

type ociImageManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
	Annotations map[string]string `json:"annotations"`
}

var tagCounter atomic.Uint64

func TestNativeChiselRealImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireLocalImage(t, chiselToolingImage)

	fixture := loadFixture(t, "canonical-native-dotnet")
	pullImage(t, fixture.Reference, fixture.Platform)
	before := captureImage(t, fixture.Reference, fixture.Platform)
	require.NotNil(t, before.Manifest)
	require.Empty(t, before.DPKGStatus)
	assertForbiddenToolingAbsent(t, &before)

	beforeRuntime := runDocker(t, fixture.Platform, fixture.Reference, "--info")
	require.Contains(t, beforeRuntime, fixture.RuntimeContains)

	patched := uniqueImage("native")
	t.Cleanup(func() { removeImage(patched) })
	patchArgs := []string{"patch", "--image", fixture.Reference, "--tag", patched, "--platform", fixture.Platform}
	patchImage(t, patchArgs...)

	after := captureImage(t, patched, fixture.Platform)
	require.NotNil(t, after.Manifest)
	require.Empty(t, after.DPKGStatus)
	assertImageConfigPreserved(t, &before.Config, &after.Config)
	assertForbiddenToolingAbsent(t, &after)
	assertManifestUpgrade(t, before.Manifest, after.Manifest, fixture.ExpectedUpgradePackages)
	assert.Equal(t, "ubuntu-24.04", after.Config.Config.Labels["sh.copa.chisel.release"])
	assert.Equal(t, "v1.4.2", after.Config.Config.Labels["sh.copa.chisel.version"])

	afterRuntime := runDocker(t, fixture.Platform, patched, "--info")
	require.Contains(t, afterRuntime, fixture.RuntimeContains)
	require.NotEqual(t, beforeRuntime, afterRuntime, "expected the .NET runtime version to change")

	assertNoUpdates(t, "patch", "--image", patched, "--tag", uniqueImage("native-repatch"), "--platform", fixture.Platform)
}

func TestNativeChiselCommunityImagePreservesApplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireLocalImage(t, chiselToolingImage)

	fixture := loadFixture(t, "community-native-sonarr")
	pullImage(t, fixture.Reference, fixture.Platform)
	before := captureImage(t, fixture.Reference, fixture.Platform)
	require.NotNil(t, before.Manifest)
	require.Empty(t, before.DPKGStatus)
	beforeTree := canonicalTreeHash(t, before.RootFSTar, fixture.PreserveTree)
	beforeRuntime := runSonarrHelp(t, fixture.Platform, fixture.Reference)
	require.Contains(t, beforeRuntime, "Version 4.0.15.2941")
	require.Contains(t, beforeRuntime, "Application mode: Help")

	patched := uniqueImage("sonarr")
	t.Cleanup(func() { removeImage(patched) })
	patchImage(t,
		"patch",
		"--image", fixture.Reference,
		"--tag", patched,
		"--platform", fixture.Platform,
		"--chisel-release", fixture.ChiselRelease,
	)

	after := captureImage(t, patched, fixture.Platform)
	require.NotNil(t, after.Manifest)
	require.Empty(t, after.DPKGStatus)
	assertImageConfigPreserved(t, &before.Config, &after.Config)
	assertForbiddenToolingAbsent(t, &after)
	assertManifestUpgrade(t, before.Manifest, after.Manifest, fixture.ExpectedUpgradePackages)
	assert.Equal(t, beforeTree, canonicalTreeHash(t, after.RootFSTar, fixture.PreserveTree))
	afterRuntime := runSonarrHelp(t, fixture.Platform, patched)
	require.Contains(t, afterRuntime, "Version 4.0.15.2941")
	require.Contains(t, afterRuntime, "Application mode: Help")
	assert.Equal(t, fixture.ChiselRelease, after.Config.Config.Labels["sh.copa.chisel.release"])
	assert.Equal(t, "v1.4.2", after.Config.Config.Labels["sh.copa.chisel.version"])

	assertNoUpdates(t,
		"patch",
		"--image", patched,
		"--tag", uniqueImage("sonarr-repatch"),
		"--platform", fixture.Platform,
		"--chisel-release", fixture.ChiselRelease,
	)
}

func TestNativeChiselPartialPlatformOCI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireLocalImage(t, chiselToolingImage)

	fixture := loadFixture(t, "canonical-native-index")
	outputDir := filepath.Join(t.TempDir(), "oci")
	patched := uniqueImage("native-index")
	t.Cleanup(func() {
		removeImage(patched + "-amd64")
	})
	patchImage(t,
		"patch",
		"--image", fixture.Reference,
		"--tag", patched,
		"--platform", fixture.Platform,
		"--chisel-release", fixture.ChiselRelease,
		"--oci-dir", outputDir,
	)

	indexData, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	require.NoError(t, err)
	var index ociIndex
	require.NoError(t, json.Unmarshal(indexData, &index))

	sourceIndexData := []byte(run(t, "docker", "buildx", "imagetools", "inspect", "--raw", fixture.Reference))
	var sourceIndex ociIndex
	require.NoError(t, json.Unmarshal(sourceIndexData, &sourceIndex))

	outputDescriptors := descriptorsByPlatform(index)
	sourceDescriptors := descriptorsByPlatform(sourceIndex)
	expectedPlatforms := []string{"linux/amd64", "linux/arm64", "linux/ppc64le", "linux/s390x"}
	for _, key := range expectedPlatforms {
		require.Contains(t, sourceDescriptors, key, "source index is missing expected platform")
		require.Contains(t, outputDescriptors, key, "output index is missing expected platform")
	}
	require.NotEqual(t, sourceDescriptors["linux/amd64"].Digest, outputDescriptors["linux/amd64"].Digest)
	for _, key := range []string{"linux/arm64", "linux/ppc64le", "linux/s390x"} {
		assert.Equal(t, sourceDescriptors[key], outputDescriptors[key], "unselected platform descriptor changed")
	}

	platformManifests := make(map[string]ociImageManifest)
	for _, descriptor := range index.Manifests {
		manifest := assertOCIManifestBlobsExist(t, outputDir, descriptor.Digest)
		if key := descriptorPlatformKey(descriptor); key != "" {
			platformManifests[key] = manifest
		}
	}
	manifest := platformManifests["linux/amd64"]
	assert.Equal(t, "ubuntu-24.04", manifest.Annotations["sh.copa.chisel.release"])
	assert.Equal(t, "v1.4.2", manifest.Annotations["sh.copa.chisel.version"])
	assertBlobExists(t, outputDir, manifest.Config.Digest)
	for _, layer := range manifest.Layers {
		assertBlobExists(t, outputDir, layer.Digest)
	}

	configData := readOCIBlob(t, outputDir, manifest.Config.Digest)
	var config struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Config       struct {
			User        string            `json:"User"`
			Entrypoint  []string          `json:"Entrypoint"`
			Cmd         []string          `json:"Cmd"`
			WorkingDir  string            `json:"WorkingDir"`
			Labels      map[string]string `json:"Labels"`
			LowerLabels map[string]string `json:"labels"`
		} `json:"config"`
	}
	require.NoError(t, json.Unmarshal(configData, &config))
	assert.Equal(t, "linux", config.OS)
	assert.Equal(t, "amd64", config.Architecture)
	assert.Equal(t, "101", config.Config.User)
	assert.Equal(t, []string{"/usr/bin/dotnet"}, config.Config.Entrypoint)
	assert.Equal(t, []string{"--info"}, config.Config.Cmd)
	assert.Equal(t, "/", config.Config.WorkingDir)
	labels := config.Config.Labels
	if labels == nil {
		labels = config.Config.LowerLabels
	}
	assert.Equal(t, "ubuntu-24.04", labels["sh.copa.chisel.release"])
	assert.Equal(t, "v1.4.2", labels["sh.copa.chisel.version"])
}

func TestAptlessFullStatusRealImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-image Chisel e2e test in short mode")
	}
	requireTool(t, "docker")
	requireTool(t, "trivy")

	fixture := loadFixture(t, "microsoft-full-status-dotnet")
	pullImage(t, fixture.Reference, fixture.Platform)
	before := captureImage(t, fixture.Reference, fixture.Platform)
	require.Nil(t, before.Manifest)
	require.NotEmpty(t, before.DPKGStatus)
	assertFullStatusLayout(t, &before)
	beforePackages := parseDPKGStatus(t, before.DPKGStatus)

	cacheDir := filepath.Join(t.TempDir(), "trivy-cache")
	integrationcommon.DownloadDBToDir(t, cacheDir)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	vulnsBefore := scanOSImage(t, fixture.Reference, reportPath, cacheDir, fixture.Platform, true)
	require.NotEmpty(t, vulnsBefore, "expected fixable OS vulnerabilities in baseline image")

	patched := uniqueImage("full-status")
	comprehensive := uniqueImage("full-status-comprehensive")
	t.Cleanup(func() {
		removeImage(patched)
		removeImage(comprehensive)
	})
	patchImage(t,
		"patch",
		"--image", fixture.Reference,
		"--report", reportPath,
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
	vulnsAfter := scanOSImage(t, patched, filepath.Join(t.TempDir(), "after.json"), cacheDir, fixture.Platform, false)
	for key, vulnerability := range vulnsBefore {
		assert.NotContains(t, vulnsAfter, key,
			"targeted vulnerability remained after patch: %s in %s", vulnerability.ID, vulnerability.Package)
	}

	beforeRuntime := runDocker(t, fixture.Platform, fixture.Reference, "--info")
	afterRuntime := runDocker(t, fixture.Platform, patched, "--info")
	assert.Equal(t, beforeRuntime, afterRuntime, "OS patching must not replace the separately copied .NET runtime")

	patchImage(t,
		"patch",
		"--image", patched,
		"--tag", comprehensive,
		"--platform", fixture.Platform,
	)
	comprehensiveSnapshot := captureImage(t, comprehensive, fixture.Platform)
	assertFullStatusLayout(t, &comprehensiveSnapshot)
	assertImageConfigPreserved(t, &before.Config, &comprehensiveSnapshot.Config)
	comprehensivePackages := parseDPKGStatus(t, comprehensiveSnapshot.DPKGStatus)
	assertNoDPKGDowngrades(t, afterPackages, comprehensivePackages)
	comprehensiveRuntime := runDocker(t, fixture.Platform, comprehensive, "--info")
	assert.Equal(t, beforeRuntime, comprehensiveRuntime, "comprehensive OS patching must not replace the separately copied .NET runtime")
	assertNoUpdates(t, "patch", "--image", comprehensive, "--tag", uniqueImage("full-status-repatch"), "--platform", fixture.Platform)
}

func loadFixture(t *testing.T, id string) realImageFixture {
	t.Helper()
	var fixtures []realImageFixture
	require.NoError(t, json.Unmarshal(fixtureData, &fixtures))
	for i := range fixtures {
		if fixtures[i].ID == id {
			return fixtures[i]
		}
	}
	t.Fatalf("fixture %q not found", id)
	return realImageFixture{}
}

func uniqueImage(prefix string) string {
	return fmt.Sprintf("copa-e2e-chisel-%s:%d-%d", prefix, time.Now().UnixNano(), tagCounter.Add(1))
}

func patchImage(t *testing.T, args ...string) string {
	t.Helper()
	args = append(args, "--loader", "docker", "--progress", "plain", "--timeout", "20m")
	if buildkitAddr != "" {
		args = append(args, "--addr", buildkitAddr)
	}
	cmd := exec.Command(copaPath, args...) //#nosec G204 -- test inputs are fixed fixture data.
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa failed:\n%s", string(output))
	return string(output)
}

func assertNoUpdates(t *testing.T, args ...string) {
	t.Helper()
	if tag := argumentValue(args, "--tag"); tag != "" {
		t.Cleanup(func() { removeImage(tag) })
	}
	args = append(args, "--loader", "docker", "--progress", "plain", "--timeout", "20m")
	if buildkitAddr != "" {
		args = append(args, "--addr", buildkitAddr)
	}
	cmd := exec.Command(copaPath, args...) //#nosec G204 -- test inputs are fixed fixture data.
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		var exitError *exec.ExitError
		require.ErrorAs(t, err, &exitError, "unexpected failure while checking no-updates result:\n%s", string(output))
	}
	lowerOutput := strings.ToLower(string(output))
	require.True(t,
		strings.Contains(lowerOutput, "no package updates found for image") || strings.Contains(lowerOutput, "already up-to-date"),
		"expected no-updates result, got:\n%s", string(output),
	)
}

func argumentValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func captureImage(t *testing.T, image, platform string) imageSnapshot {
	t.Helper()
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "rootfs.tar")
	containerID := strings.TrimSpace(run(t, "docker", "create", "--platform", platform, image))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })
	run(t, "docker", "export", "--output", tarPath, containerID)
	run(t, "docker", "rm", containerID)

	inspectBytes := []byte(run(t, "docker", "image", "inspect", image))
	var configs []imageConfig
	require.NoError(t, json.Unmarshal(inspectBytes, &configs))
	require.Len(t, configs, 1)

	snapshot := imageSnapshot{
		Config:    configs[0],
		Paths:     make(map[string]pathMetadata),
		RootFSTar: tarPath,
	}
	file, err := os.Open(tarPath)
	require.NoError(t, err)
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		require.NoError(t, nextErr)
		name := strings.TrimPrefix(filepath.ToSlash(header.Name), "./")
		snapshot.Paths[name] = pathMetadata{
			Type:     header.Typeflag,
			Mode:     header.Mode,
			UID:      header.Uid,
			GID:      header.Gid,
			Size:     header.Size,
			Linkname: header.Linkname,
		}
		switch name {
		case "var/lib/chisel/manifest.wall":
			snapshot.ManifestData, err = io.ReadAll(reader)
			require.NoError(t, err)
		case "var/lib/dpkg/status":
			snapshot.DPKGStatus, err = io.ReadAll(reader)
			require.NoError(t, err)
		}
	}
	if len(snapshot.ManifestData) > 0 {
		snapshot.Manifest, err = copachisel.ParseManifest(bytes.NewReader(snapshot.ManifestData))
		require.NoError(t, err)
	}
	return snapshot
}

func canonicalTreeHash(t *testing.T, tarPath, prefix string) string {
	t.Helper()
	file, err := os.Open(tarPath)
	require.NoError(t, err)
	defer file.Close()

	var records []string
	reader := tar.NewReader(file)
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		require.NoError(t, nextErr)
		name := strings.TrimPrefix(filepath.ToSlash(header.Name), "./")
		normalizedPrefix := strings.TrimSuffix(filepath.ToSlash(prefix), "/")
		if name != normalizedPrefix && !strings.HasPrefix(name, normalizedPrefix+"/") {
			continue
		}
		contentDigest := ""
		if header.FileInfo().Mode().IsRegular() {
			hash := sha256.New()
			// #nosec G110 -- tar.Reader bounds reads to the current entry in a pinned image fixture.
			_, err = io.Copy(hash, reader)
			require.NoError(t, err)
			contentDigest = hex.EncodeToString(hash.Sum(nil))
		}
		records = append(records, fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%s\x00%s",
			name, header.Typeflag, header.Mode, header.Uid, header.Gid, header.Size, header.Linkname, contentDigest))
	}
	sort.Strings(records)
	hash := sha256.New()
	for _, record := range records {
		_, err = io.WriteString(hash, record)
		require.NoError(t, err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func assertManifestUpgrade(t *testing.T, before, after *copachisel.Manifest, requiredPackages []string) {
	t.Helper()
	oldSlices := make(map[string]struct{}, len(before.Slices))
	for _, slice := range before.Slices {
		oldSlices[slice] = struct{}{}
	}
	newSlices := make(map[string]struct{}, len(after.Slices))
	for _, slice := range after.Slices {
		newSlices[slice] = struct{}{}
	}
	for slice := range oldSlices {
		assert.Contains(t, newSlices, slice, "original Chisel slice was lost")
	}

	upgraded := 0
	for name, oldPackage := range before.Packages {
		newPackage, ok := after.Packages[name]
		require.True(t, ok, "original package %s disappeared", name)
		comparison := compareDebianVersions(t, newPackage.Version, oldPackage.Version)
		require.GreaterOrEqual(t, comparison, 0, "package %s was downgraded", name)
		if comparison > 0 {
			upgraded++
		}
	}
	for name, newPackage := range after.Packages {
		require.NotEmpty(t, newPackage.Architecture, "package %s is missing its architecture", name)
		require.Len(t, newPackage.SHA256, 64, "package %s is missing its archive digest", name)
	}
	require.Positive(t, upgraded, "expected at least one native Chisel package upgrade")
	for _, name := range requiredPackages {
		requireVersionGreater(t, after.Packages[name].Version, before.Packages[name].Version, name)
	}
}

func assertNoDPKGDowngrades(t *testing.T, before, after map[string]statusPackage) {
	t.Helper()
	for name, oldPackage := range before {
		newPackage, ok := after[name]
		require.True(t, ok, "original package %s disappeared", name)
		require.GreaterOrEqual(t, compareDebianVersions(t, newPackage.Version, oldPackage.Version), 0,
			"package %s was downgraded", name)
		require.NotEmpty(t, newPackage.Architecture, "package %s is missing its architecture", name)
	}
}

func compareDebianVersions(t *testing.T, left, right string) int {
	t.Helper()
	leftVersion, err := debversion.NewVersion(left)
	require.NoError(t, err)
	rightVersion, err := debversion.NewVersion(right)
	require.NoError(t, err)
	switch {
	case leftVersion.LessThan(rightVersion):
		return -1
	case rightVersion.LessThan(leftVersion):
		return 1
	default:
		return 0
	}
}

func requireVersionGreater(t *testing.T, actual, previous, packageName string) {
	t.Helper()
	require.NotEmpty(t, actual, "package %s missing after patch", packageName)
	require.NotEmpty(t, previous, "package %s missing before patch", packageName)
	require.Greater(t, compareDebianVersions(t, actual, previous), 0, "package %s was not upgraded", packageName)
}

func assertImageConfigPreserved(t *testing.T, before, after *imageConfig) {
	t.Helper()
	assert.Equal(t, before.Architecture, after.Architecture)
	assert.Equal(t, before.OS, after.OS)
	assert.Equal(t, before.Config.User, after.Config.User)
	assert.Equal(t, before.Config.Entrypoint, after.Config.Entrypoint)
	assert.Equal(t, before.Config.Cmd, after.Config.Cmd)
	assert.Equal(t, before.Config.Env, after.Config.Env)
	assert.Equal(t, before.Config.WorkingDir, after.Config.WorkingDir)
	assert.Equal(t, before.Config.Healthcheck, after.Config.Healthcheck)
	assert.Equal(t, before.Config.ExposedPorts, after.Config.ExposedPorts)
	assert.Equal(t, before.Config.Volumes, after.Config.Volumes)
	assert.Equal(t, before.Config.StopSignal, after.Config.StopSignal)
	for key, value := range before.Config.Labels {
		assert.Equal(t, value, after.Config.Labels[key], "existing image label changed")
	}
}

func assertForbiddenToolingAbsent(t *testing.T, snapshot *imageSnapshot) {
	t.Helper()
	for _, path := range []string{
		"bin/sh", "bin/bash", "bin/busybox",
		"usr/bin/apt", "usr/bin/apt-get", "usr/bin/apt-mark", "usr/bin/dpkg",
		"usr/bin/dpkg-query", "usr/bin/sh", "usr/bin/grep", "usr/bin/tee",
	} {
		assert.NotContains(t, snapshot.Paths, path)
	}
	for path := range snapshot.Paths {
		assert.False(t, strings.HasPrefix(path, "usr/bin/apt-"), "apt helper leaked into patched image: %s", path)
	}
}

func assertFullStatusLayout(t *testing.T, snapshot *imageSnapshot) {
	t.Helper()
	require.NotEmpty(t, snapshot.DPKGStatus)
	require.Nil(t, snapshot.Manifest)
	assert.NotContains(t, snapshot.Paths, "var/lib/dpkg/status.d")
	for path := range snapshot.Paths {
		assert.False(t, strings.HasPrefix(path, "var/lib/dpkg/status.d/"))
	}
	assertForbiddenToolingAbsent(t, snapshot)
}

func parseDPKGStatus(t *testing.T, data []byte) map[string]statusPackage {
	t.Helper()
	packages := make(map[string]statusPackage)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(splitParagraphs)
	for scanner.Scan() {
		var name, version, architecture string
		for _, line := range strings.Split(scanner.Text(), "\n") {
			switch {
			case strings.HasPrefix(line, "Package: "):
				name = strings.TrimPrefix(line, "Package: ")
			case strings.HasPrefix(line, "Version: "):
				version = strings.TrimPrefix(line, "Version: ")
			case strings.HasPrefix(line, "Architecture: "):
				architecture = strings.TrimPrefix(line, "Architecture: ")
			}
		}
		if name != "" {
			packages[name] = statusPackage{Version: version, Architecture: architecture}
		}
	}
	require.NoError(t, scanner.Err())
	return packages
}

func splitParagraphs(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if index := bytes.Index(data, []byte("\n\n")); index >= 0 {
		return index + 2, bytes.TrimSpace(data[:index]), nil
	}
	if atEOF {
		return len(data), bytes.TrimSpace(data), nil
	}
	return 0, nil, nil
}

func scanOSImage(t *testing.T, image, reportPath, cacheDir, platform string, remote bool) map[string]trivyVulnerability {
	t.Helper()
	args := []string{
		"image", "--quiet", "--format=json", "--output", reportPath,
		"--pkg-types=os", "--scanners=vuln", "--ignore-unfixed", "--skip-db-update", "--cache-dir", cacheDir,
	}
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	if remote {
		args = append(args, "--image-src", "remote")
	} else {
		args = append(args, "--image-src", "docker")
	}
	args = append(args, image)
	run(t, "trivy", args...)

	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report trivyReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, "ubuntu", report.Metadata.OS.Family, "Trivy did not recognize the image as Ubuntu")
	unique := make(map[string]trivyVulnerability)
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if vulnerability.FixedVersion == "" {
				continue
			}
			key := strings.Join([]string{
				vulnerability.ID,
				vulnerability.Package,
				vulnerability.InstalledVersion,
				vulnerability.FixedVersion,
			}, "|")
			unique[key] = vulnerability
		}
	}
	return unique
}

func runSonarrHelp(t *testing.T, platform, image string) string {
	t.Helper()
	return run(t,
		"docker", "run", "--rm", "--platform", platform,
		"--network", "none", "--read-only",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=128m",
		"--env", "HOME=/tmp", "--env", "DOTNET_CLI_HOME=/tmp",
		"--entrypoint", "/Sonarr/Sonarr", image, "/?",
	)
}

func runDocker(t *testing.T, platform, image string, args ...string) string {
	t.Helper()
	command := []string{"run", "--rm", "--platform", platform, "--network", "none", "--read-only", image}
	command = append(command, args...)
	return run(t, "docker", command...)
}

func pullImage(t *testing.T, image, platform string) {
	t.Helper()
	run(t, "docker", "pull", "--platform", platform, image)
}

func requireLocalImage(t *testing.T, image string) {
	t.Helper()
	cmd := exec.Command("docker", "image", "inspect", image)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err,
		"required pinned tooling image %s is unavailable; pull it with `docker pull --platform linux/amd64 %s`:\n%s",
		image, image, string(output))
}

func requireTool(t *testing.T, name string) {
	t.Helper()
	_, err := exec.LookPath(name)
	require.NoError(t, err, "required tool %s not found", name)
}

func descriptorsByPlatform(index ociIndex) map[string]ociDescriptor {
	descriptors := make(map[string]ociDescriptor)
	for _, descriptor := range index.Manifests {
		if key := descriptorPlatformKey(descriptor); key != "" {
			descriptors[key] = descriptor
		}
	}
	return descriptors
}

func descriptorPlatformKey(descriptor ociDescriptor) string {
	if descriptor.Platform == nil || descriptor.Platform.OS == "" || descriptor.Platform.Architecture == "" {
		return ""
	}
	key := descriptor.Platform.OS + "/" + descriptor.Platform.Architecture
	if descriptor.Platform.Variant != "" {
		key += "/" + descriptor.Platform.Variant
	}
	return key
}

func readOCIBlob(t *testing.T, outputDir, digest string) []byte {
	t.Helper()
	parts := strings.SplitN(digest, ":", 2)
	require.Len(t, parts, 2)
	data, err := os.ReadFile(filepath.Join(outputDir, "blobs", parts[0], parts[1]))
	require.NoError(t, err)
	return data
}

func assertOCIManifestBlobsExist(t *testing.T, outputDir, digest string) ociImageManifest {
	t.Helper()
	assertBlobExists(t, outputDir, digest)
	data := readOCIBlob(t, outputDir, digest)
	var manifest ociImageManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.NotEmpty(t, manifest.Config.Digest)
	assertBlobExists(t, outputDir, manifest.Config.Digest)
	for _, layer := range manifest.Layers {
		require.NotEmpty(t, layer.Digest)
		assertBlobExists(t, outputDir, layer.Digest)
	}
	return manifest
}

func assertBlobExists(t *testing.T, outputDir, digest string) {
	t.Helper()
	parts := strings.SplitN(digest, ":", 2)
	require.Len(t, parts, 2)
	path := filepath.Join(outputDir, "blobs", parts[0], parts[1])
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())

	if parts[0] == "sha256" {
		file, err := os.Open(path)
		require.NoError(t, err)
		defer file.Close()
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		require.NoError(t, err)
		assert.Equal(t, parts[1], hex.EncodeToString(hash.Sum(nil)), "OCI blob digest mismatch")
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...) //#nosec G204 -- commands use fixed test fixtures.
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %s failed:\n%s", name, strings.Join(args, " "), string(output))
	return string(output)
}

func removeImage(image string) {
	_ = exec.Command("docker", "image", "rm", "--force", image).Run()
}
