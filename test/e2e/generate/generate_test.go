package generate

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateWithReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// check if we can run docker commands for this test
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping test; docker binary not found in path")
	}

	testImage := "nginx:1.21.6-alpine"

	// create a temp directory for test files
	tempDir, err := os.MkdirTemp("", "copa-generate-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// create a sample trivy report file
	reportFile := filepath.Join(tempDir, "report.json")
	reportContent := `{
		"SchemaVersion": 2,
		"ArtifactName": "nginx:1.21.6-alpine",
		"ArtifactType": "container_image",
		"Metadata": {
			"OS": {
				"Family": "alpine",
				"Name": "3.15.4"
			}
		},
		"Results": [
			{
				"Target": "nginx:1.21.6-alpine (alpine 3.15.4)",
				"Class": "os-pkgs",
				"Type": "alpine",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2022-37434",
						"PkgName": "zlib",
						"InstalledVersion": "1.2.12-r0",
						"FixedVersion": "1.2.12-r2",
						"Severity": "CRITICAL"
					}
				]
			}
		]
	}`
	err = os.WriteFile(reportFile, []byte(reportContent), 0o600)
	require.NoError(t, err, "failed to create sample report file")

	// run copa generate with report
	outputFile := filepath.Join(tempDir, "build-context.tar")
	generateCmd := exec.Command(
		copaPath,
		"generate",
		"--image", testImage,
		"--report", reportFile,
		"--output-context", outputFile,
		"-a="+buildkitAddr,
	)

	output, err := generateCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to generate build context: %s", string(output)))

	// verify the tar file was created
	require.FileExists(t, outputFile, "build context tar file should exist")

	// verify tar file contents
	validateTarContents(t, outputFile, testImage)

	// test docker build with the generated context
	buildContextDir := filepath.Join(tempDir, "build-context")
	err = os.MkdirAll(buildContextDir, 0o755)
	require.NoError(t, err, "failed to create build context directory")

	// extract tar file
	extractTar(t, outputFile, buildContextDir)

	// build the image using docker
	patchedImage := "nginx:1.21.6-alpine-patched-test"
	buildCmd := exec.Command("docker", "build", "-t", patchedImage, buildContextDir)
	buildOutput, err := buildCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to build patched image: %s", string(buildOutput)))

	// verify the patched image was created
	inspectCmd := exec.Command("docker", "inspect", patchedImage)
	err = inspectCmd.Run()
	require.NoError(t, err, "patched image should exist")

	// clean up
	removeLocalImage(t, patchedImage)
}

func TestGenerateWithoutReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// check if we can run docker commands for this test
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping test; docker binary not found in path")
	}

	testImage := "alpine:3.18"

	// create a temp directory for test files
	tempDir, err := os.MkdirTemp("", "copa-generate-no-report-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// run copa generate without report (should update all packages)
	outputFile := filepath.Join(tempDir, "build-context.tar")
	generateCmd := exec.Command(
		copaPath,
		"generate",
		"--image", testImage,
		"--output-context", outputFile,
		"-a="+buildkitAddr,
	)

	output, err := generateCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to generate build context: %s", string(output)))

	// verify the tar file was created
	require.FileExists(t, outputFile, "build context tar file should exist")

	// verify tar file contents
	validateTarContents(t, outputFile, testImage)

	// test docker build with the generated context
	buildContextDir := filepath.Join(tempDir, "build-context")
	err = os.MkdirAll(buildContextDir, 0o755)
	require.NoError(t, err, "failed to create build context directory")

	// extract tar file
	extractTar(t, outputFile, buildContextDir)

	// build the image using docker
	patchedImage := "alpine:3.18-patched-test"
	buildCmd := exec.Command("docker", "build", "-t", patchedImage, buildContextDir)
	buildOutput, err := buildCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to build patched image: %s", string(buildOutput)))

	// verify the patched image was created
	inspectCmd := exec.Command("docker", "inspect", patchedImage)
	err = inspectCmd.Run()
	require.NoError(t, err, "patched image should exist")

	// clean up
	removeLocalImage(t, patchedImage)
}

func TestGenerateToStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// check if we can run docker commands for this test
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping test; docker binary not found in path")
	}

	testImage := "alpine:3.18"

	// run copa generate and pipe to docker build
	patchedImage := "alpine:3.18-piped-test"

	// create a shell command that pipes copa generate to docker build
	shellCmd := fmt.Sprintf(
		"%s generate --image %s -a=%s | docker build -t %s -",
		copaPath, testImage, buildkitAddr, patchedImage,
	)

	pipeCmd := exec.Command("bash", "-c", shellCmd)
	output, err := pipeCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to pipe generate to docker build: %s", string(output)))

	// verify the patched image was created
	inspectCmd := exec.Command("docker", "inspect", patchedImage)
	err = inspectCmd.Run()
	require.NoError(t, err, "patched image should exist")

	// clean up
	removeLocalImage(t, patchedImage)
}

func validateTarContents(t *testing.T, tarFile, expectedImage string) {
	// open and read the tar file
	file, err := os.Open(tarFile)
	require.NoError(t, err, "failed to open tar file")
	defer file.Close()

	tr := tar.NewReader(file)

	foundDockerfile := false
	foundPatchDir := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "failed to read tar entry")

		switch hdr.Name {
		case "Dockerfile":
			foundDockerfile = true
			// read and validate Dockerfile contents
			dockerfileContent, err := io.ReadAll(tr)
			require.NoError(t, err, "failed to read Dockerfile content")

			dockerfileStr := string(dockerfileContent)
			require.Contains(t, dockerfileStr, fmt.Sprintf("FROM %s", expectedImage), "Dockerfile should contain correct FROM instruction")
			require.Contains(t, dockerfileStr, "COPY patch/ /", "Dockerfile should contain COPY instruction")
			require.Contains(t, dockerfileStr, "LABEL sh.copa.image.patched=", "Dockerfile should contain patched label")
		default:
			if strings.HasPrefix(hdr.Name, "patch/") {
				foundPatchDir = true
			}
		}
	}

	require.True(t, foundDockerfile, "tar should contain Dockerfile")
	require.True(t, foundPatchDir, "tar should contain patch/ directory with files")
}

func extractTar(t *testing.T, tarFile, destDir string) {
	file, err := os.Open(tarFile)
	require.NoError(t, err, "failed to open tar file")
	defer file.Close()

	tr := tar.NewReader(file)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "failed to read tar entry")

		target := filepath.Join(destDir, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			err := os.MkdirAll(target, os.FileMode(hdr.Mode))
			require.NoError(t, err, "failed to create directory")
		case tar.TypeReg:
			// create parent directories if needed
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				require.NoError(t, err, "failed to create parent directory")
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(hdr.Mode))
			require.NoError(t, err, "failed to create file")

			_, err = io.Copy(f, tr)
			f.Close()
			require.NoError(t, err, "failed to copy file content")
		}
	}
}

func removeLocalImage(_ *testing.T, image string) {
	cmd := exec.Command("docker", "rmi", "-f", image)
	_ = cmd.Run()
}
