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

const (
	nginxImage = "nginx:1.21.6"
)

// generateTrivyReport generates a vulnerability report using Trivy for the specified image.
func generateTrivyReport(t *testing.T, image, reportFile string) {
	// Check if trivy is available
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("skipping test; trivy binary not found in path")
	}

	// Run trivy scan to generate vulnerability report
	cmd := exec.Command("trivy", "image", "--vuln-type", "os", "--ignore-unfixed", "-f", "json", "-o", reportFile, image)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to generate trivy report: %s", string(output)))

	// Verify report file exists and has content
	require.FileExists(t, reportFile, "trivy report should be generated")

	// Verify the report file is not empty
	info, err := os.Stat(reportFile)
	require.NoError(t, err, "failed to stat trivy report file")
	require.Greater(t, info.Size(), int64(0), "trivy report should not be empty")
}

func TestGenerateWithReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// check if we can run docker commands for this test
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping test; docker binary not found in path")
	}

	// create a temp directory for test files
	tempDir, err := os.MkdirTemp("", "copa-generate-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// generate vulnerability report using Trivy
	reportFile := filepath.Join(tempDir, "report.json")
	generateTrivyReport(t, nginxImage, reportFile)

	// run copa generate with report
	outputFile := filepath.Join(tempDir, "build-context.tar")
	generateCmd := exec.Command(
		copaPath,
		"generate",
		"--image", nginxImage,
		"--report", reportFile,
		"--output-context", outputFile,
		"-a="+buildkitAddr,
	)

	output, err := generateCmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("failed to generate build context: %s", string(output)))

	// verify the tar file was created
	require.FileExists(t, outputFile, "build context tar file should exist")

	// verify tar file contents
	validateTarContents(t, outputFile, nginxImage)

	// test docker build with the generated context
	buildContextDir := filepath.Join(tempDir, "build-context")
	err = os.MkdirAll(buildContextDir, 0o755)
	require.NoError(t, err, "failed to create build context directory")

	// extract tar file
	extractTar(t, outputFile, buildContextDir)

	// build the image using docker
	patchedImage := "nginx:1.21.6-patched-test"
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

	testImage := "nginx:1.21.6"

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
	patchedImage := "nginx:1.21.6-patched-test"
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

	testImage := "nginx:1.21.6"

	// run copa generate and pipe to docker build
	patchedImage := "nginx:1.21.6-piped-test"

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

		// Sanitize the file path to prevent directory traversal
		target := filepath.Join(destDir, filepath.Clean(hdr.Name))
		// Ensure the target path is within destDir
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			t.Fatalf("tar entry %s would extract outside of target directory", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			// Use a safe mode conversion with bounds checking
			// #nosec G115 -- hdr.Mode is a file mode from tar header, safe to convert after masking
			mode := os.FileMode(uint32(hdr.Mode & 0o777))
			err := os.MkdirAll(target, mode)
			require.NoError(t, err, "failed to create directory")
		case tar.TypeReg:
			// create parent directories if needed
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				require.NoError(t, err, "failed to create parent directory")
			}

			// Use a safe mode conversion with bounds checking
			// #nosec G115 -- hdr.Mode is a file mode from tar header, safe to convert after masking
			mode := os.FileMode(uint32(hdr.Mode & 0o777))
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, mode)
			require.NoError(t, err, "failed to create file")

			// Limit the amount of data to copy to prevent decompression bombs
			limited := io.LimitReader(tr, 100*1024*1024) // 100MB limit
			_, err = io.Copy(f, limited)
			f.Close()
			require.NoError(t, err, "failed to copy file content")
		}
	}
}

func removeLocalImage(_ *testing.T, image string) {
	cmd := exec.Command("docker", "rmi", "-f", image)
	_ = cmd.Run()
}
