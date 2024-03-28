package patch

import "testing"

func TestNewPatchCmd(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "Missing image flag",
			args:     []string{"-r", "trivy.json", "-t", "3.7-alpine-patched"},
			expected: "required flag(s) \"image\" not set",
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new command with the test args
			cmd := NewPatchCmd()
			cmd.SetArgs(tt.args)

			// Run the command and capture the output
			err := cmd.Execute()
			if err == nil || err.Error() != tt.expected {
				t.Errorf("Unexpected error: %v, expected: %v", err, tt.expected)
			}
		})
	}
}
