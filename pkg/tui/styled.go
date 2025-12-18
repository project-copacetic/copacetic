package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var (
	// Style colors
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	success   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	warning   = lipgloss.AdaptiveColor{Light: "#FFA500", Dark: "#FFB347"}
	errorClr  = lipgloss.AdaptiveColor{Light: "#FF5555", Dark: "#FF6666"}
	dim       = lipgloss.AdaptiveColor{Light: "#666666", Dark: "#888888"}

	// Text styles (no boxes)
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(highlight)
	successStyle = lipgloss.NewStyle().Foreground(success)
	warningStyle = lipgloss.NewStyle().Foreground(warning)
	errorStyle   = lipgloss.NewStyle().Foreground(errorClr).Bold(true)
	dimStyle     = lipgloss.NewStyle().Foreground(dim)
	boldStyle    = lipgloss.NewStyle().Bold(true)
)

// PatchingPlan represents the patching plan to display.
type PatchingPlan struct {
	TargetPlatform     string
	PatchedImageName   string
	PreservedPlatforms []string
}

// RenderPatchingPlan renders the patching plan with colors.
func RenderPatchingPlan(plan PatchingPlan) string {
	if !isTerminal() {
		return renderPatchingPlanPlain(plan)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("📦 Patching Plan") + "\n")
	b.WriteString("   ")
	b.WriteString(dimStyle.Render("Target: "))
	b.WriteString(boldStyle.Render(plan.TargetPlatform))
	b.WriteString(" → ")
	b.WriteString(successStyle.Render(plan.PatchedImageName))
	b.WriteString("\n")

	if len(plan.PreservedPlatforms) > 0 {
		b.WriteString("   ")
		b.WriteString(dimStyle.Render("Preserve: "))
		b.WriteString(warningStyle.Render(strings.Join(plan.PreservedPlatforms, ", ")))
		b.WriteString("\n")
	}
	return b.String()
}

func renderPatchingPlanPlain(plan PatchingPlan) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Patching: %s -> %s", plan.TargetPlatform, plan.PatchedImageName))
	if len(plan.PreservedPlatforms) > 0 {
		b.WriteString(fmt.Sprintf(" (preserving: %s)", strings.Join(plan.PreservedPlatforms, ", ")))
	}
	b.WriteString("\n")
	return b.String()
}

// NextSteps represents the next steps to display after patching.
type NextSteps struct {
	PushCommands    []string
	ManifestCommand string
	SuccessMessage  string
}

// RenderNextSteps renders next steps with colors.
func RenderNextSteps(steps NextSteps) string {
	if !isTerminal() {
		return renderNextStepsPlain(steps)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("🚀 Next Steps") + "\n")

	if steps.SuccessMessage != "" {
		b.WriteString("   ")
		b.WriteString(successStyle.Render("✓ "+steps.SuccessMessage) + "\n")
	}

	stepNum := 1
	if len(steps.PushCommands) > 0 {
		b.WriteString(fmt.Sprintf("   %s Push architecture images:\n", boldStyle.Render(fmt.Sprintf("%d.", stepNum))))
		for _, cmd := range steps.PushCommands {
			b.WriteString(fmt.Sprintf("      %s\n", dimStyle.Render(cmd)))
		}
		stepNum++
	}
	if steps.ManifestCommand != "" {
		b.WriteString(fmt.Sprintf("   %s Create multi-platform manifest:\n", boldStyle.Render(fmt.Sprintf("%d.", stepNum))))
		b.WriteString(fmt.Sprintf("      %s\n", dimStyle.Render(steps.ManifestCommand)))
	}
	return b.String()
}

func renderNextStepsPlain(steps NextSteps) string {
	var b strings.Builder
	if steps.SuccessMessage != "" {
		b.WriteString(fmt.Sprintf("✓ %s\n", steps.SuccessMessage))
	}
	stepNum := 1
	if len(steps.PushCommands) > 0 {
		b.WriteString(fmt.Sprintf("%d. Push architecture images:\n", stepNum))
		for _, cmd := range steps.PushCommands {
			b.WriteString(fmt.Sprintf("   %s\n", cmd))
		}
		stepNum++
	}
	if steps.ManifestCommand != "" {
		b.WriteString(fmt.Sprintf("%d. Create multi-platform manifest:\n", stepNum))
		b.WriteString(fmt.Sprintf("   %s\n", steps.ManifestCommand))
	}
	return b.String()
}

// PlatformSummary represents the summary for a single platform.
type PlatformSummary struct {
	Platform string
	Status   string
	Ref      string
	Message  string
}

// RenderPatchSummary renders a summary of patched platforms with colors.
func RenderPatchSummary(summaries []PlatformSummary) string {
	if !isTerminal() {
		return renderPatchSummaryPlain(summaries)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("📋 Summary") + "\n")

	for _, s := range summaries {
		b.WriteString("   ")
		b.WriteString(formatStatusStyled(s.Status))
		b.WriteString(fmt.Sprintf(" %-16s ", s.Platform))
		if s.Message != "" {
			b.WriteString(dimStyle.Render(s.Message))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func formatStatusStyled(status string) string {
	switch status {
	case "Patched":
		return successStyle.Render("✓ Patched    ")
	case "Not Patched":
		return warningStyle.Render("○ Preserved  ")
	case "Up-to-date":
		return successStyle.Render("✓ Up-to-date ")
	case "Error":
		return errorStyle.Render("✗ Error      ")
	case "Ignored":
		return warningStyle.Render("⊘ Ignored    ")
	default:
		return fmt.Sprintf("  %-12s", status)
	}
}

func renderPatchSummaryPlain(summaries []PlatformSummary) string {
	var b strings.Builder
	for _, s := range summaries {
		statusIcon := getStatusIcon(s.Status)
		b.WriteString(fmt.Sprintf("%s %-16s %-12s %s\n", statusIcon, s.Platform, s.Status, s.Message))
	}
	return b.String()
}

func getStatusIcon(status string) string {
	switch status {
	case "Patched":
		return "✓"
	case "Not Patched":
		return "○"
	case "Up-to-date":
		return "✓"
	case "Error":
		return "✗"
	case "Ignored":
		return "⊘"
	default:
		return " "
	}
}

// ErrorInfo contains information about an error to display.
type ErrorInfo struct {
	Title   string
	Message string
	Hint    string
}

// RenderError renders an error message with colors.
func RenderError(info ErrorInfo) string {
	if !isTerminal() {
		return renderErrorPlain(info)
	}

	var b strings.Builder
	b.WriteString(errorStyle.Render("❌ "+info.Title) + "\n")
	b.WriteString("   ")
	b.WriteString(errorStyle.Render("✗ " + info.Message))
	b.WriteString("\n")

	if info.Hint != "" {
		b.WriteString("   ")
		b.WriteString(dimStyle.Render("💡 "+info.Hint) + "\n")
	}
	return b.String()
}

func renderErrorPlain(info ErrorInfo) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Error: %s\n", info.Title))
	b.WriteString(fmt.Sprintf("  %s\n", info.Message))
	if info.Hint != "" {
		b.WriteString(fmt.Sprintf("  Hint: %s\n", info.Hint))
	}
	return b.String()
}

// isTerminal checks if stdout is a terminal.
func isTerminal() bool {
	// We print UI output to both stdout and stderr depending on call site.
	// Prefer enabling styles when either stream is a TTY to avoid losing colors
	// when e.g. stdout is redirected but stderr is still interactive.
	return term.IsTerminal(int(os.Stdout.Fd())) || term.IsTerminal(int(os.Stderr.Fd()))
}
