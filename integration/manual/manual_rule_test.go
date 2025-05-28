package manual

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestValidManualRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	imageName, err := reference.ParseNamed("docker.io/library/nginx:1.21.6")
	require.NoError(t, err, "failed to parse image name")

	manualRuleFile := filepath.Join("testdata", "valid_manual_rule.yaml")

	rules, err := parseManualRuleFile(manualRuleFile)
	require.NoError(t, err, "failed to parse manual rule file")
	require.Len(t, rules.Rules, 1, "expected exactly one rule")

	tag := "patched-manual"
	//#nosec G204
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", imageName.String(),
		"--manual-rule", manualRuleFile,
		"--tag", tag,
		"-a", buildkitAddr,
	)
	patchCmd.Stdout = os.Stderr
	patchCmd.Stderr = os.Stderr

	err = patchCmd.Run()
	require.NoError(t, err, "failed to patch image with manual rule")

	patchedImageName, err := reference.WithTag(imageName, tag)
	require.NoError(t, err, "failed to create patched image name")

	// verify the file was replaced using buildkit
	// use the path from the rule as source of truth
	rule := rules.Rules[0]
	verifyFileReplaced(t, patchedImageName.String(), rule.Target.Path, rule.Replacement.Sha256, rule.Replacement.Mode)

	removeLocalImage(t, patchedImageName.String())
	removeLocalImage(t, imageName.String())
}

func TestManualRuleWithShaValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	imageName, err := reference.ParseNamed("docker.io/library/alpine:3.17")
	require.NoError(t, err, "failed to parse image name")

	tempDir, err := os.MkdirTemp("", "copa-manual-rule-test-*")
	require.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(tempDir)

	actualSHA := getFileSHA(t, imageName.String(), "/etc/alpine-release")

	templateContent, err := os.ReadFile(filepath.Join("testdata", "sha_validation_template.yaml"))
	require.NoError(t, err, "failed to read template file")

	manualRuleContent := strings.Replace(string(templateContent), "{{SHA256}}", actualSHA, 1)

	manualRuleFile := filepath.Join(tempDir, "manual-rule.yaml")
	err = os.WriteFile(manualRuleFile, []byte(manualRuleContent), 0o600)
	require.NoError(t, err, "failed to create manual rule file")

	rules, err := parseManualRuleFile(manualRuleFile)
	require.NoError(t, err, "failed to parse manual rule file")
	require.Len(t, rules.Rules, 1, "expected exactly one rule")

	tag := "patched-sha-valid"
	//#nosec G204
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", imageName.String(),
		"--manual-rule", manualRuleFile,
		"--tag", tag,
		"-a", buildkitAddr,
	)
	patchCmd.Stdout = os.Stderr
	patchCmd.Stderr = os.Stderr

	err = patchCmd.Run()
	require.NoError(t, err, "failed to patch image with valid SHA")

	patchedImageName, err := reference.WithTag(imageName, tag)
	require.NoError(t, err, "failed to create patched image name")

	rule := rules.Rules[0]
	verifyFileReplaced(t, patchedImageName.String(), rule.Target.Path, rule.Replacement.Sha256, rule.Replacement.Mode)

	removeLocalImage(t, patchedImageName.String())
	removeLocalImage(t, imageName.String())
}

func TestManualRuleWithInvalidSha(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	imageName, err := reference.ParseNamed("docker.io/library/alpine:3.17")
	require.NoError(t, err, "failed to parse image name")

	manualRuleFile := filepath.Join("testdata", "invalid_sha_rule.yaml")

	_, err = parseManualRuleFile(manualRuleFile)
	require.NoError(t, err, "failed to parse manual rule file")

	// should fail due to SHA mismatch
	//#nosec G204
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", imageName.String(),
		"--manual-rule", manualRuleFile,
		"--tag", "patched-sha-invalid",
		"-a", buildkitAddr,
	)
	var outputBuf strings.Builder
	patchCmd.Stdout = io.MultiWriter(os.Stderr, &outputBuf)
	patchCmd.Stderr = io.MultiWriter(os.Stderr, &outputBuf)

	err = patchCmd.Run()
	require.Error(t, err, "expected error for SHA mismatch")
	require.Contains(t, outputBuf.String(), "sha mismatch", "expected sha mismatch error message")

	removeLocalImage(t, imageName.String())
}

func TestManualRuleWithInvalidPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	imageName, err := reference.ParseNamed("docker.io/library/nginx:1.21.6")
	require.NoError(t, err, "failed to parse image name")

	manualRuleFile := filepath.Join("testdata", "invalid_path_rule.yaml")

	_, err = parseManualRuleFile(manualRuleFile)
	require.NoError(t, err, "failed to parse manual rule file")

	// should fail due to invalid path in the rule
	//#nosec G204
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", imageName.String(),
		"--manual-rule", manualRuleFile,
		"--tag", "patched-invalid",
		"-a", buildkitAddr,
	)
	var outputBuf strings.Builder
	patchCmd.Stdout = io.MultiWriter(os.Stderr, &outputBuf)
	patchCmd.Stderr = io.MultiWriter(os.Stderr, &outputBuf)

	err = patchCmd.Run()
	require.Error(t, err, "expected error for invalid path")
	require.Contains(t, outputBuf.String(), "failed to extract", "expected extraction error message")

	removeLocalImage(t, imageName.String())
}

func TestManualRuleWithMultipleFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	imageName, err := reference.ParseNamed("docker.io/library/nginx:1.21.6")
	require.NoError(t, err, "failed to parse image name")

	manualRuleFile := filepath.Join("testdata", "multiple_replacements.yaml")

	rules, err := parseManualRuleFile(manualRuleFile)
	require.NoError(t, err, "failed to parse manual rule file")
	require.Len(t, rules.Rules, 2, "expected exactly two rules")

	// multiple rules in one go
	tag := "patched-multi"
	//#nosec G204
	patchCmd := exec.Command(
		copaPath,
		"patch",
		"--image", imageName.String(),
		"--manual-rule", manualRuleFile,
		"--tag", tag,
		"-a", buildkitAddr,
	)
	patchCmd.Stdout = os.Stderr
	patchCmd.Stderr = os.Stderr

	err = patchCmd.Run()
	require.NoError(t, err, "failed to apply patches")

	patchedImage, err := reference.WithTag(imageName, tag)
	require.NoError(t, err)

	// verify both files were replaced using values from parsed rules
	for _, rule := range rules.Rules {
		verifyFileReplaced(t, patchedImage.String(), rule.Target.Path, rule.Replacement.Sha256, rule.Replacement.Mode)
	}

	removeLocalImage(t, patchedImage.String())
	removeLocalImage(t, imageName.String())
}

// Helper functions.

func parseManualRuleFile(filePath string) (*patch.ManualRules, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file: %w", err)
	}

	var rules patch.ManualRules
	err = yaml.Unmarshal(data, &rules)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return &rules, nil
}

func verifyFileReplaced(t *testing.T, image, filePath, expectedSHA string, expectedMode uint32) {
	ctx := context.Background()

	// create buildkit client
	bkOpts := buildkit.Opts{Addr: buildkitAddr}
	bkClient, err := buildkit.NewClient(ctx, bkOpts)
	require.NoError(t, err, "failed to create buildkit client")
	defer bkClient.Close()

	// set up auth
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{ConfigFile: dockerConfig}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}

	solveOpt := client.SolveOpt{
		Frontend: "",
		Session:  attachable,
	}

	_, err = bkClient.Build(ctx, solveOpt, "copa-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		config, err := buildkit.InitializeBuildkitConfig(ctx, c, image)
		require.NoError(t, err, "failed to initialize buildkit config")

		platform := platforms.Normalize(platforms.DefaultSpec())
		if platform.OS != "linux" {
			platform.OS = "linux"
		}

		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "failed to marshal image state")

		resp, err := c.Solve(ctx, gwclient.SolveRequest{
			Evaluate:   true,
			Definition: def.ToPB(),
		})
		require.NoError(t, err, "failed to solve image state")

		ref, err := resp.SingleRef()
		require.NoError(t, err, "failed to get single ref")

		stat, err := ref.StatFile(ctx, gwclient.StatRequest{
			Path: filePath,
		})
		require.NoError(t, err, fmt.Sprintf("failed to stat file %s", filePath))

		fileBytes, err := ref.ReadFile(ctx, gwclient.ReadRequest{
			Filename: filePath,
		})
		require.NoError(t, err, fmt.Sprintf("failed to extract file %s from image", filePath))

		require.NotEmpty(t, fileBytes, "extracted file should not be empty")

		sum := sha256.Sum256(fileBytes)
		fileSHA := fmt.Sprintf("%x", sum)

		actualMode := stat.Mode
		t.Logf("File %s: size=%d, mode=%04o, SHA256=%s", filePath, len(fileBytes), actualMode, fileSHA)

		if expectedSHA != "" {
			require.Equal(t, expectedSHA, fileSHA, "SHA256 mismatch for file %s", filePath)
		}

		if expectedMode != 0 {
			require.Equal(t, expectedMode, actualMode, "File mode mismatch for file %s", filePath)
		}

		// for known replacements, verify the content
		// since were replacing with busybox binaries, we can check if its an ELF executable
		if filePath == "/usr/share/nginx/html/index.html" || filePath == "/usr/share/nginx/html/50x.html" {
			// elf files start with 0x7f 'E' 'L' 'F'
			if len(fileBytes) >= 4 && fileBytes[0] == 0x7f && fileBytes[1] == 'E' && fileBytes[2] == 'L' && fileBytes[3] == 'F' {
				t.Logf("File %s was successfully replaced with an ELF binary", filePath)
			} else {
				t.Errorf("File %s does not appear to be an ELF binary as expected", filePath)
			}
		}

		return &gwclient.Result{}, nil
	}, nil)

	require.NoError(t, err, "failed to verify file in image")
}

func getFileSHA(t *testing.T, image, filePath string) string {
	ctx := context.Background()

	bkOpts := buildkit.Opts{Addr: buildkitAddr}
	bkClient, err := buildkit.NewClient(ctx, bkOpts)
	require.NoError(t, err, "failed to create buildkit client")
	defer bkClient.Close()

	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{ConfigFile: dockerConfig}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}

	solveOpt := client.SolveOpt{
		Frontend: "",
		Session:  attachable,
	}

	var fileSHA string
	_, err = bkClient.Build(ctx, solveOpt, "copa-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		config, err := buildkit.InitializeBuildkitConfig(ctx, c, image)
		require.NoError(t, err, "failed to initialize buildkit config")

		fileBytes, err := buildkit.ExtractFileFromState(ctx, c, &config.ImageState, filePath)
		require.NoError(t, err, fmt.Sprintf("failed to extract file %s from image", filePath))

		sum := sha256.Sum256(fileBytes)
		fileSHA = fmt.Sprintf("%x", sum)

		return &gwclient.Result{}, nil
	}, nil)

	require.NoError(t, err, "failed to get file SHA")
	return fileSHA
}

func removeLocalImage(_ *testing.T, image string) {
	cmd := exec.Command("docker", "rmi", "-f", image)
	_ = cmd.Run()
}
