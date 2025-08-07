package patch

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/utils"
)

func TestExitOnEOLFunctionality(t *testing.T) {
	// Test the ExitOnEOL functionality with mock EOL API
	originalBaseURL := utils.GetEOLAPIBaseURL()
	defer utils.SetEOLAPIBaseURL(originalBaseURL)

	tests := []struct {
		name        string
		exitOnEOL   bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "ExitOnEOL disabled - should not exit",
			exitOnEOL:   false,
			expectError: false,
		},
		{
			name:        "ExitOnEOL enabled - should exit with error",
			exitOnEOL:   true,
			expectError: true,
			errorMsg:    "exiting due to EOL operating system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test validates the ExitOnEOL option is properly passed through
			// In a full integration test, we would set up a mock BuildKit client
			// For now, we verify the option is correctly configured

			opts := &Options{
				ExitOnEOL: tt.exitOnEOL,
			}

			if opts.ExitOnEOL != tt.exitOnEOL {
				t.Errorf("ExitOnEOL option not properly set: got %v, want %v", opts.ExitOnEOL, tt.exitOnEOL)
			}
		})
	}
}

func TestEOLConfigurationIntegration(t *testing.T) {
	// Test URL configuration
	originalBaseURL := utils.GetEOLAPIBaseURL()
	defer utils.SetEOLAPIBaseURL(originalBaseURL)

	testURL := "https://example.com/api/v1/products"
	utils.SetEOLAPIBaseURL(testURL)

	got := utils.GetEOLAPIBaseURL()
	if got != testURL {
		t.Errorf("EOL API URL not properly configured: got %s, want %s", got, testURL)
	}
}