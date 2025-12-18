package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderPatchingPlan(t *testing.T) {
	plan := PatchingPlan{
		TargetPlatform:     "linux/amd64",
		PatchedImageName:   "nginx:1.27.0-patched",
		PreservedPlatforms: []string{"linux/arm64", "linux/arm"},
	}

	// Uses plain mode in tests (not a terminal)
	result := renderPatchingPlanPlain(plan)

	assert.Contains(t, result, "linux/amd64")
	assert.Contains(t, result, "nginx:1.27.0-patched")
	assert.Contains(t, result, "linux/arm64")
	assert.Contains(t, result, "linux/arm")
}

func TestRenderPatchingPlanNoPreserved(t *testing.T) {
	plan := PatchingPlan{
		TargetPlatform:     "linux/amd64",
		PatchedImageName:   "nginx:1.27.0-patched",
		PreservedPlatforms: []string{},
	}

	result := renderPatchingPlanPlain(plan)

	assert.Contains(t, result, "linux/amd64")
	assert.Contains(t, result, "nginx:1.27.0-patched")
	assert.NotContains(t, result, "preserving")
}

func TestRenderNextSteps(t *testing.T) {
	steps := NextSteps{
		SuccessMessage:  "Image loaded successfully",
		PushCommands:    []string{"docker push nginx:1.27.0-patched-amd64"},
		ManifestCommand: "docker buildx imagetools create --tag nginx:1.27.0-patched ...",
	}

	result := renderNextStepsPlain(steps)

	assert.Contains(t, result, "Image loaded successfully")
	assert.Contains(t, result, "docker push nginx:1.27.0-patched-amd64")
	assert.Contains(t, result, "docker buildx imagetools create")
}

func TestRenderNextStepsNoPushCommands(t *testing.T) {
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

func TestRenderNextStepsNoManifest(t *testing.T) {
	steps := NextSteps{
		SuccessMessage:  "Image loaded successfully",
		PushCommands:    []string{"docker push nginx:1.27.0-patched"},
		ManifestCommand: "",
	}

	result := renderNextStepsPlain(steps)

	assert.Contains(t, result, "1. Push architecture images")
	assert.NotContains(t, result, "2.")
}

func TestRenderPatchingPlanManyPreservedPlatforms(t *testing.T) {
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

	result := renderPatchingPlanPlain(plan)
	assert.Contains(t, result, "linux/arm64")
	assert.Contains(t, result, "linux/arm/v5")
	assert.Contains(t, result, "linux/arm/v7")
	assert.Contains(t, result, "linux/s390x")
}

func TestRenderNextStepsMultiplePushCommands(t *testing.T) {
	steps := NextSteps{
		SuccessMessage: "Images loaded",
		PushCommands: []string{
			"docker push nginx:1.27.0-patched-amd64",
			"docker push nginx:1.27.0-patched-arm64",
		},
		ManifestCommand: "docker buildx imagetools create ...",
	}

	result := renderNextStepsPlain(steps)

	assert.Contains(t, result, "1. Push architecture images")
	assert.Contains(t, result, "nginx:1.27.0-patched-amd64")
	assert.Contains(t, result, "nginx:1.27.0-patched-arm64")
	assert.Contains(t, result, "2. Create multi-platform manifest")
}

func TestRenderPatchSummary(t *testing.T) {
	summaries := []PlatformSummary{
		{Platform: "linux/amd64", Status: "Patched", Message: "OK"},
		{Platform: "linux/arm64", Status: "Up-to-date", Message: ""},
		{Platform: "linux/arm", Status: "Error", Message: "failed"},
	}

	result := renderPatchSummaryPlain(summaries)

	assert.Contains(t, result, "linux/amd64")
	assert.Contains(t, result, "Patched")
	assert.Contains(t, result, "linux/arm64")
	assert.Contains(t, result, "Up-to-date")
	assert.Contains(t, result, "linux/arm")
	assert.Contains(t, result, "Error")
}

func TestRenderError(t *testing.T) {
	info := ErrorInfo{
		Title:   "Connection Failed",
		Message: "Failed to connect to buildkit",
		Hint:    "Check that buildkit is running",
	}

	result := renderErrorPlain(info)

	assert.Contains(t, result, "Connection Failed")
	assert.Contains(t, result, "Failed to connect to buildkit")
	assert.Contains(t, result, "Check that buildkit is running")
}

func TestRenderErrorNoHint(t *testing.T) {
	info := ErrorInfo{
		Title:   "Patch Failed",
		Message: "Some error occurred",
		Hint:    "",
	}

	result := renderErrorPlain(info)

	assert.Contains(t, result, "Patch Failed")
	assert.Contains(t, result, "Some error occurred")
	assert.NotContains(t, result, "Hint:")
}
