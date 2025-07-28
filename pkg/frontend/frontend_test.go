package frontend

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestParsePlatform(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *ispec.Platform
		hasError bool
	}{
		{
			name:  "linux/amd64",
			input: "linux/amd64",
			expected: &ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			hasError: false,
		},
		{
			name:  "linux/arm64/v8",
			input: "linux/arm64/v8",
			expected: &ispec.Platform{
				OS:           "linux",
				Architecture: "arm64",
				Variant:      "v8",
			},
			hasError: false,
		},
		{
			name:     "invalid",
			input:    "linux",
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePlatform(tt.input)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
