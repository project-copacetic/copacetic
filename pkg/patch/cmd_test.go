package patch

import "testing"

func TestNewPatchCmd(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		expected  bool
		errString string
	}{
		{
			name:      "Missing image flag",
			args:      []string{"-r", "trivy.json", "-t", "3.7-alpine-patched"},
			expected:  true,
			errString: "required flag(s) \"image\" not set",
		},
		{
			name:      "Silent flag used",
			args:      []string{"-t", "3.7-alpine-patched", "-i", "alpine:3.14", "--silent"},
			expected:  false,
			errString: "",
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
			if !tt.expected {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error: %v, got %v", tt.expected, err)
				} else if err != nil && err.Error() != tt.errString {
					t.Errorf("Unexpected error: %v, expected: %v", err, tt.expected)
				}
			}
		})
	}
}
