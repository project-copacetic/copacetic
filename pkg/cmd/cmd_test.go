package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			expectedErrorContains: "one of --image, --config, or --chart must be provided",
		},
		{
			name:                  "FAIL: Conflicting flags (--config and --image)",
			args:                  []string{"--config", "config.yaml", "--image", "alpine"},
			expectValidationError: true,
			expectedErrorContains: "--image, --config, and --chart are mutually exclusive",
		},
		{
			name:                  "FAIL: Conflicting flags (--config and --chisel-release)",
			args:                  []string{"--config", "config.yaml", "--chisel-release", "ubuntu-24.04"},
			expectValidationError: true,
			expectedErrorContains: "--chisel-release cannot be used with --config",
		},
		{
			name:                  "PASS: Single image mode validation",
			args:                  []string{"--image", "alpine:latest"},
			expectValidationError: false, // This combination of flags is valid.
		},
		{
			name:                  "PASS: Local export compression flags",
			args:                  []string{"--image", "alpine:latest", "--compression", "gzip", "--force-compression"},
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

func TestNewPatchCmdChiselReleaseFlag(t *testing.T) {
	cmd := NewPatchCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--chisel-release", "ubuntu-24.04"}))

	flag := cmd.Flags().Lookup("chisel-release")
	require.NotNil(t, flag)
	assert.Equal(t, "ubuntu-24.04", flag.Value.String())
}

func TestNewPatchCmdConfigHelp(t *testing.T) {
	flag := NewPatchCmd().Flags().Lookup("config")
	require.NotNil(t, flag)
	assert.NotContains(t, flag.Usage, "Comprehensive update only")
	assert.Contains(t, flag.Usage, "bulk patch YAML config file")
}
