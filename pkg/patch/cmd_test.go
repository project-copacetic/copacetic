/*
Copyright (c) Project Copacetic authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
		{
			name:     "Missing report flag",
			args:     []string{"-i", "images/python:3.7-alpine", "-t", "3.7-alpine-patched"},
			expected: "required flag(s) \"report\" not set",
		},
		{
			name:     "Missing report flag with ignore-errors flag",
			args:     []string{"-i", "images/python:3.7-alpine", "-t", "3.7-alpine-patched", "--ignore-errors"},
			expected: "required flag(s) \"report\" not set",
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
