package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderPatchingPlanPlain(t *testing.T) {
	plan := PatchingPlan{
		TargetPlatform:     "linux/amd64",
		PatchedImageName:   "nginx:1.27.0-patched",
		PreservedPlatforms: []string{"linux/arm64", "linux/arm"},
	}

	result := renderPatchingPlanPlain(plan)

	assert.Contains(t, result, "Patching Plan")
	assert.Contains(t, result, "linux/amd64")
	assert.Contains(t, result, "nginx:1.27.0-patched")
	assert.Contains(t, result, "linux/arm64")
	assert.Contains(t, result, "linux/arm")
}

func TestRenderPatchingPlanPlainNoPreserved(t *testing.T) {
	plan := PatchingPlan{
		TargetPlatform:     "linux/amd64",
		PatchedImageName:   "nginx:1.27.0-patched",
		PreservedPlatforms: []string{},
	}

	result := renderPatchingPlanPlain(plan)

	assert.Contains(t, result, "linux/amd64")
	assert.Contains(t, result, "nginx:1.27.0-patched")
	assert.NotContains(t, result, "Preserve:")
}

func TestRenderNextStepsPlain(t *testing.T) {
	steps := NextSteps{
		SuccessMessage:  "Image loaded successfully",
		PushCommands:    []string{"docker push nginx:1.27.0-patched-amd64"},
		ManifestCommand: "docker buildx imagetools create --tag nginx:1.27.0-patched ...",
	}

	result := renderNextStepsPlain(steps)

	assert.Contains(t, result, "Next Steps")
	assert.Contains(t, result, "Image loaded successfully")
	assert.Contains(t, result, "docker push nginx:1.27.0-patched-amd64")
	assert.Contains(t, result, "docker buildx imagetools create")
}

func TestRenderNextStepsPlainNoPushCommands(t *testing.T) {
	steps := NextSteps{
		SuccessMessage:  "Image loaded successfully",
		PushCommands:    []string{},
		ManifestCommand: "docker buildx imagetools create --tag nginx:1.27.0-patched",
	}

	result := renderNextStepsPlain(steps)

	assert.Contains(t, result, "Image loaded successfully")
	assert.Contains(t, result, "1. Create multi-platform manifest")
	assert.NotContains(t, result, "2.")
}

func TestRenderNextStepsPlainNoManifest(t *testing.T) {
	steps := NextSteps{
		SuccessMessage:  "Image loaded successfully",
		PushCommands:    []string{"docker push nginx:1.27.0-patched"},
		ManifestCommand: "",
	}

	result := renderNextStepsPlain(steps)

	assert.Contains(t, result, "1. Push architecture images")
	assert.NotContains(t, result, "2.")
}

func TestPatchingPlanManyPreservedPlatforms(t *testing.T) {
	plan := PatchingPlan{
		TargetPlatform:   "linux/amd64",
		PatchedImageName: "nginx:1.27.0-patched",
		PreservedPlatforms: []string{
			"linux/arm64",
			"linux/arm/v5",
			"linux/arm/v7",
			"linux/386",
			"linux/ppc64le",
			"linux/s390x",
		},
	}

	// Plain should list all platforms including ARM variants
	result := renderPatchingPlanPlain(plan)
	assert.Contains(t, result, "linux/arm64")
	assert.Contains(t, result, "linux/arm/v5")
	assert.Contains(t, result, "linux/arm/v7")
	assert.Contains(t, result, "linux/s390x")
}

func TestNextStepsMultiplePushCommands(t *testing.T) {
	steps := NextSteps{
		SuccessMessage: "Images loaded",
		PushCommands: []string{
			"docker push nginx:1.27.0-patched-amd64",
			"docker push nginx:1.27.0-patched-arm64",
		},
		ManifestCommand: "docker buildx imagetools create ...",
	}

	result := renderNextStepsPlain(steps)

	// Should have step 1 for push and step 2 for manifest
	assert.Contains(t, result, "1. Push architecture images")
	assert.Contains(t, result, "nginx:1.27.0-patched-amd64")
	assert.Contains(t, result, "nginx:1.27.0-patched-arm64")
	assert.Contains(t, result, "2. Create multi-platform manifest")
}

func TestRenderPatchingPlanTerminal(t *testing.T) {
	// Since we can't easily test terminal output, at least verify it doesn't panic
	// and returns something when isTerminal is false (which it will be in tests)
	plan := PatchingPlan{
		TargetPlatform:     "linux/amd64",
		PatchedImageName:   "nginx:1.27.0-patched",
		PreservedPlatforms: []string{"linux/arm64"},
	}

	result := RenderPatchingPlan(plan)
	assert.NotEmpty(t, result)
	// Should fall back to plain since not a terminal
	assert.True(t, strings.Contains(result, "Patching Plan") || strings.Contains(result, "📦"))
}

func TestRenderNextStepsTerminal(t *testing.T) {
	steps := NextSteps{
		SuccessMessage:  "Image loaded",
		PushCommands:    []string{"docker push nginx:1.27.0-patched"},
		ManifestCommand: "docker buildx imagetools create ...",
	}

	result := RenderNextSteps(steps)
	assert.NotEmpty(t, result)
	// Should fall back to plain since not a terminal
	assert.True(t, strings.Contains(result, "Next Steps") || strings.Contains(result, "🚀"))
}
