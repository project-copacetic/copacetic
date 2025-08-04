package bulk

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTagStrategy_UnmarshalYAML(t *testing.T) {
	testCases := []struct {
		name      string
		yamlInput string
		expectErr bool
		checkFunc func(*TagStrategy) bool // Optional check for successful unmarshals
	}{
		{
			name: "Valid Strategy - List",
			yamlInput: `
strategy: "list"
list: ["tag1", "tag2"]`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "list" && len(ts.List) == 2
			},
		},
		{
			name: "Invalid Strategy - List without items",
			yamlInput: `strategy: "list"
									list: []`,
			expectErr: true,
		},
		{
			name: "Valid Strategy - Pattern",
			yamlInput: `
strategy: "pattern"
pattern: "^1\\.2[0-9]+$"`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "pattern" && ts.compiledPattern != nil
			},
		},
		{
			name:      "Invalid Strategy - Pattern without pattern string",
			yamlInput: `strategy: "pattern"`,
			expectErr: true,
		},
		{
			name: "Invalid Strategy - Pattern with bad regex",
			yamlInput: `strategy: "pattern"
									pattern: "*not-a-valid-regex"`,
			expectErr: true,
		},
		{
			name:      "Valid Strategy - Latest",
			yamlInput: `strategy: "latest"`,
			expectErr: false,
			checkFunc: func(ts *TagStrategy) bool {
				return ts.Strategy == "latest"
			},
		},
		{
			name:      "Invalid Strategy - Unknown",
			yamlInput: `strategy: "unknown"`,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ts TagStrategy
			err := yaml.Unmarshal([]byte(tc.yamlInput), &ts)

			if (err != nil) != tc.expectErr {
				t.Errorf("Expected error: %v, but got: %v", tc.expectErr, err)
			}

			if !tc.expectErr && tc.checkFunc != nil {
				if !tc.checkFunc(&ts) {
					t.Errorf("Post-unmarshal check failed for valid case")
				}
			}
		})
	}
}
