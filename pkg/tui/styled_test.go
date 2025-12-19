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

func TestRequiresEmulation(t *testing.T) {
	tests := []struct {
		name       string
		hostArch   string
		targetArch string
		want       bool
	}{
		// Same architecture - no emulation
		{name: "amd64 to amd64", hostArch: "amd64", targetArch: "amd64", want: false},
		{name: "arm64 to arm64", hostArch: "arm64", targetArch: "arm64", want: false},
		{name: "386 to 386", hostArch: "386", targetArch: "386", want: false},
		{name: "arm to arm", hostArch: "arm", targetArch: "arm", want: false},

		// Native compatibility - no emulation
		{name: "amd64 to 386 (32-bit compat)", hostArch: "amd64", targetArch: "386", want: false},
		{name: "arm64 to arm (AArch32 compat)", hostArch: "arm64", targetArch: "arm", want: false},

		// Cross-architecture - requires emulation
		{name: "amd64 to arm64", hostArch: "amd64", targetArch: "arm64", want: true},
		{name: "amd64 to arm", hostArch: "amd64", targetArch: "arm", want: true},
		{name: "amd64 to mips64le", hostArch: "amd64", targetArch: "mips64le", want: true},
		{name: "amd64 to ppc64le", hostArch: "amd64", targetArch: "ppc64le", want: true},
		{name: "amd64 to s390x", hostArch: "amd64", targetArch: "s390x", want: true},
		{name: "amd64 to riscv64", hostArch: "amd64", targetArch: "riscv64", want: true},

		// arm64 host cross-compilation
		{name: "arm64 to amd64", hostArch: "arm64", targetArch: "amd64", want: true},
		{name: "arm64 to 386", hostArch: "arm64", targetArch: "386", want: true},

		// Other hosts
		{name: "386 to amd64", hostArch: "386", targetArch: "amd64", want: true},
		{name: "arm to arm64", hostArch: "arm", targetArch: "arm64", want: true},
		{name: "ppc64le to amd64", hostArch: "ppc64le", targetArch: "amd64", want: true},
		{name: "s390x to amd64", hostArch: "s390x", targetArch: "amd64", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := requiresEmulation(tt.hostArch, tt.targetArch)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatEmulationPrefix(t *testing.T) {
	tests := []struct {
		name          string
		hostArch      string
		targetArch    string
		targetVariant string
		wantContains  string
		wantNoArrow   bool
	}{
		// Same architecture - no arrow
		{
			name:         "amd64 native",
			hostArch:     "amd64",
			targetArch:   "amd64",
			wantContains: "amd64",
			wantNoArrow:  true,
		},
		{
			name:         "arm64 native",
			hostArch:     "arm64",
			targetArch:   "arm64",
			wantContains: "arm64",
			wantNoArrow:  true,
		},
		// Native compat - no arrow
		{
			name:         "amd64 to 386 compat",
			hostArch:     "amd64",
			targetArch:   "386",
			wantContains: "386",
			wantNoArrow:  true,
		},
		{
			name:         "arm64 to arm compat",
			hostArch:     "arm64",
			targetArch:   "arm",
			wantContains: "arm",
			wantNoArrow:  true,
		},
		// With variant - no arrow for compat
		{
			name:          "arm64 to arm/v7 compat",
			hostArch:      "arm64",
			targetArch:    "arm",
			targetVariant: "v7",
			wantContains:  "arm/v7",
			wantNoArrow:   true,
		},
		// Cross-architecture - arrow shown (uses ASCII in tests since not TTY)
		{
			name:         "amd64 to arm64 emulated",
			hostArch:     "amd64",
			targetArch:   "arm64",
			wantContains: "amd64 -> arm64",
			wantNoArrow:  false,
		},
		{
			name:         "amd64 to mips64le emulated",
			hostArch:     "amd64",
			targetArch:   "mips64le",
			wantContains: "amd64 -> mips64le",
			wantNoArrow:  false,
		},
		{
			name:          "amd64 to arm/v7 emulated",
			hostArch:      "amd64",
			targetArch:    "arm",
			targetVariant: "v7",
			wantContains:  "amd64 -> arm/v7",
			wantNoArrow:   false,
		},
		// arm64 host emulation
		{
			name:         "arm64 to amd64 emulated",
			hostArch:     "arm64",
			targetArch:   "amd64",
			wantContains: "arm64 -> amd64",
			wantNoArrow:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatEmulationPrefix(tt.hostArch, tt.targetArch, tt.targetVariant)
			assert.Contains(t, got, tt.wantContains)
			if tt.wantNoArrow {
				assert.NotContains(t, got, "->")
				assert.NotContains(t, got, "→")
			}
		})
	}
}

func TestGetStatusIcon(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"Patched", "✓"},
		{"Not Patched", "○"},
		{"Up-to-date", "✓"},
		{"Error", "✗"},
		{"Ignored", "⊘"},
		{"Unknown", " "},
		{"", " "},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := getStatusIcon(tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}
