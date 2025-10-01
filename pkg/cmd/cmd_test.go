package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestNewPatchCmdValidation(t *testing.T) {
	tests := []struct {
		name                  string
		args                  []string
		expectValidationError bool
		expectedErrorContains string
	}{
		{
			name:                  "FAIL: No flags provided",
			args:                  []string{},
			expectValidationError: true,
			expectedErrorContains: "either --config or --image must be provided",
		},
		{
			name:                  "FAIL: Conflicting flags (--config and --image)",
			args:                  []string{"--config", "config.yaml", "--image", "alpine"},
			expectValidationError: true,
			expectedErrorContains: "--config cannot be used with --image, --report, or --tag",
		},
		{
			name:                  "PASS: Single image mode validation",
			args:                  []string{"--image", "alpine:latest"},
			expectValidationError: false, // This combination of flags is valid.
		},
		{
			name:                  "PASS: Bulk mode validation",
			args:                  []string{"--config", "config.yaml"},
			expectValidationError: false, // This combination of flags is valid.
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new command with the test args
			cmd := NewPatchCmd()
			cmd.SetArgs(tt.args)

			if !tt.expectValidationError {
				cmd.RunE = func(_ *cobra.Command, _ []string) error {
					return errors.New("validation passed")
				}
			}

			// Run the command and capture the output
			err := cmd.Execute()

			if tt.expectValidationError {
				assert.Error(t, err, "Expected a validation error, but got none")
				assert.Contains(t, err.Error(), tt.expectedErrorContains, "Error message did not match")
			} else {
				assert.Error(t, err)
				assert.Equal(t, "validation passed", err.Error(), "Expected to see the dummy error, indicating validation passed")
			}
		})
	}
}
