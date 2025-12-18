package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var (
	// Style colors.
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	warning   = lipgloss.AdaptiveColor{Light: "#FFA500", Dark: "#FFB347"}

	// Box styles.
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(highlight).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(highlight).
			MarginBottom(0)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	valueStyle = lipgloss.NewStyle().
			Foreground(special)

	commandStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#AAAAAA")).
			Background(lipgloss.Color("#2D2D2D")).
			Padding(0, 1)

	stepNumberStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(special)

	preserveStyle = lipgloss.NewStyle().
			Foreground(warning)
)

// PatchingPlan represents the patching plan to display.
type PatchingPlan struct {
	TargetPlatform     string
	PatchedImageName   string
	PreservedPlatforms []string
}

// RenderPatchingPlan renders a compact box showing the patching plan.
func RenderPatchingPlan(plan PatchingPlan) string {
	if !isTerminal() {
		return renderPatchingPlanPlain(plan)
	}

	// Get terminal width for responsive layout
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 40 {
		width = 80 // Default width
	}

	var content strings.Builder

	// Target line
	content.WriteString(labelStyle.Render("Target:   "))
	content.WriteString(valueStyle.Render(plan.TargetPlatform))
	content.WriteString(" → ")
	content.WriteString(successStyle.Render(plan.PatchedImageName))
	content.WriteString("\n")

	// Preserved platforms
	content.WriteString(labelStyle.Render("Preserve: "))
	if len(plan.PreservedPlatforms) == 0 {
		content.WriteString(labelStyle.Render("none"))
	} else {
		// Calculate if platforms fit on one line (accounting for box padding and label)
		platformsStr := strings.Join(plan.PreservedPlatforms, ", ")
		availableWidth := width - 20 // Account for label, box borders, padding

		if len(platformsStr) <= availableWidth {
			// Fits on one line
			content.WriteString(preserveStyle.Render(platformsStr))
		} else {
			// Display as a compact list
			content.WriteString(preserveStyle.Render(fmt.Sprintf("%d platforms", len(plan.PreservedPlatforms))))
			content.WriteString("\n")
			// Show platforms in a wrapped format
			lineLen := 10 // Starting indent
			for i, p := range plan.PreservedPlatforms {
				if i == 0 {
					content.WriteString("          ")
				}
				pStr := p
				if i < len(plan.PreservedPlatforms)-1 {
					pStr += ", "
				}
				if lineLen+len(pStr) > availableWidth && lineLen > 10 {
					content.WriteString("\n          ")
					lineLen = 10
				}
				content.WriteString(preserveStyle.Render(pStr))
				lineLen += len(pStr)
			}
		}
	}

	// Create the box with title
	title := titleStyle.Render("📦 Patching Plan")
	box := boxStyle.Render(content.String())

	return title + "\n" + box
}

func renderPatchingPlanPlain(plan PatchingPlan) string {
	var b strings.Builder
	b.WriteString("=== Patching Plan ===\n")
	b.WriteString(fmt.Sprintf("Target:   %s -> %s\n", plan.TargetPlatform, plan.PatchedImageName))
	if len(plan.PreservedPlatforms) > 0 {
		b.WriteString(fmt.Sprintf("Preserve: %s\n", strings.Join(plan.PreservedPlatforms, ", ")))
	}
	b.WriteString("=====================\n")
	return b.String()
}

// NextSteps represents the next steps to display after patching.
type NextSteps struct {
	PushCommands    []string
	ManifestCommand string
	SuccessMessage  string
}

// RenderNextSteps renders styled next steps without a box.
func RenderNextSteps(steps NextSteps) string {
	if !isTerminal() {
		return renderNextStepsPlain(steps)
	}

	var result strings.Builder

	// Title
	result.WriteString(titleStyle.Render("🚀 Next Steps"))
	result.WriteString("\n\n")

	// Success message
	if steps.SuccessMessage != "" {
		result.WriteString("   ")
		result.WriteString(successStyle.Render("✓ " + steps.SuccessMessage))
		result.WriteString("\n\n")
	}

	stepNum := 1

	// Push commands
	if len(steps.PushCommands) > 0 {
		result.WriteString("   ")
		result.WriteString(stepNumberStyle.Render(fmt.Sprintf("%d. ", stepNum)))
		result.WriteString("Push architecture images:\n")
		for _, cmd := range steps.PushCommands {
			result.WriteString("      ")
			result.WriteString(commandStyle.Render(cmd))
			result.WriteString("\n")
		}
		stepNum++
		result.WriteString("\n")
	}

	// Manifest command
	if steps.ManifestCommand != "" {
		result.WriteString("   ")
		result.WriteString(stepNumberStyle.Render(fmt.Sprintf("%d. ", stepNum)))
		result.WriteString("Create multi-platform manifest:\n")
		// Split command into lines with backslash continuation
		parts := strings.Fields(steps.ManifestCommand)
		for i, part := range parts {
			switch {
			case i == 0:
				result.WriteString("      " + part)
			case i <= 3:
				// Keep "docker buildx imagetools create --tag <tag>" on first line
				result.WriteString(" " + part)
			default:
				result.WriteString(" \\\n        " + part)
			}
		}
		result.WriteString("\n")
	}

	return result.String()
}

func renderNextStepsPlain(steps NextSteps) string {
	var b strings.Builder
	b.WriteString("=== Next Steps ===\n")
	if steps.SuccessMessage != "" {
		b.WriteString(fmt.Sprintf("✓ %s\n\n", steps.SuccessMessage))
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
	b.WriteString("==================\n")
	return b.String()
}

// PlatformSummary represents the summary for a single platform.
type PlatformSummary struct {
	Platform string
	Status   string
	Ref      string
	Message  string
}

var (
	// Status styles.
	statusPatched    = lipgloss.NewStyle().Foreground(special).Bold(true)
	statusNotPatched = lipgloss.NewStyle().Foreground(warning)
	statusError      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)
	statusUpToDate   = lipgloss.NewStyle().Foreground(lipgloss.Color("#88FF88"))
	dimStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
)

// RenderPatchSummary renders a styled summary table of patched platforms.
func RenderPatchSummary(summaries []PlatformSummary) string {
	if !isTerminal() {
		return renderPatchSummaryPlain(summaries)
	}

	var content strings.Builder

	for _, s := range summaries {
		// Platform name
		content.WriteString(fmt.Sprintf("%-16s ", s.Platform))

		// Status with color
		statusStr := formatStatus(s.Status)
		content.WriteString(statusStr)
		content.WriteString(" ")

		// Message (truncate if too long)
		msg := s.Message
		if len(msg) > 40 {
			msg = msg[:37] + "..."
		}
		content.WriteString(dimStyle.Render(msg))
		content.WriteString("\n")
	}

	// Create the box with title
	title := titleStyle.Render("📋 Patch Summary")
	box := boxStyle.Render(strings.TrimSuffix(content.String(), "\n"))

	return title + "\n" + box
}

func formatStatus(status string) string {
	switch status {
	case "Patched":
		return statusPatched.Render("✓ Patched")
	case "Not Patched":
		return statusNotPatched.Render("○ Preserved")
	case "Up-to-date":
		return statusUpToDate.Render("✓ Up-to-date")
	case "Error":
		return statusError.Render("✗ Error")
	case "Ignored":
		return statusNotPatched.Render("⊘ Ignored")
	default:
		return status
	}
}

func renderPatchSummaryPlain(summaries []PlatformSummary) string {
	var b strings.Builder
	b.WriteString("=== Patch Summary ===\n")
	for _, s := range summaries {
		b.WriteString(fmt.Sprintf("%-16s %-12s %s\n", s.Platform, s.Status, s.Message))
	}
	b.WriteString("=====================\n")
	return b.String()
}

// ErrorInfo contains information about an error to display.
type ErrorInfo struct {
	Title   string
	Message string
	Hint    string
}

var (
	errorTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF5555"))

	errorBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FF5555")).
			Padding(0, 1)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Italic(true)
)

// RenderError renders a styled error message.
func RenderError(info ErrorInfo) string {
	if !isTerminal() {
		return renderErrorPlain(info)
	}

	var content strings.Builder

	// Error message
	content.WriteString(statusError.Render("✗ " + info.Message))

	// Hint if provided
	if info.Hint != "" {
		content.WriteString("\n\n")
		content.WriteString(hintStyle.Render("💡 " + info.Hint))
	}

	// Create the box with title
	title := errorTitleStyle.Render("❌ " + info.Title)
	box := errorBoxStyle.Render(content.String())

	return title + "\n" + box
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
	return term.IsTerminal(int(os.Stdout.Fd()))
}

var (
	spinnerStyle = lipgloss.NewStyle().Foreground(highlight)
	statusStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
)

// StatusSpinner provides a simple inline status indicator.
type StatusSpinner struct {
	message string
	done    bool
}

// NewStatusSpinner creates a status message that can be updated.
func NewStatusSpinner(message string) *StatusSpinner {
	s := &StatusSpinner{message: message}
	if isTerminal() {
		// Print initial status with spinner
		fmt.Fprintf(os.Stderr, "%s %s", spinnerStyle.Render("⏳"), statusStyle.Render(message))
	}
	return s
}

// Done marks the status as complete and updates the display.
func (s *StatusSpinner) Done(success bool) {
	if s.done {
		return
	}
	s.done = true

	if isTerminal() {
		// Clear the line and print completion status
		fmt.Fprintf(os.Stderr, "\r\033[K") // Clear line
		if success {
			fmt.Fprintf(os.Stderr, "%s %s\n", successStyle.Render("✓"), statusStyle.Render(s.message))
		} else {
			fmt.Fprintf(os.Stderr, "%s %s\n", statusError.Render("✗"), statusStyle.Render(s.message))
		}
	}
}

// Fail marks the status as failed.
func (s *StatusSpinner) Fail() {
	s.Done(false)
}
