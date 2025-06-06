package patch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateLibraryPkgTypesRequireReport(t *testing.T) {
	tests := []struct {
		name           string
		pkgTypes       []string
		reportProvided bool
		expectError    bool
		errorMessage   string
	}{
		{
			name:           "OS package types without report - should succeed",
			pkgTypes:       []string{PkgTypeOS},
			reportProvided: false,
			expectError:    false,
		},
		{
			name:           "OS package types with report - should succeed",
			pkgTypes:       []string{PkgTypeOS},
			reportProvided: true,
			expectError:    false,
		},
		{
			name:           "Library package types with report - should succeed",
			pkgTypes:       []string{PkgTypeLibrary},
			reportProvided: true,
			expectError:    false,
		},
		{
			name:           "Library package types without report - should fail",
			pkgTypes:       []string{PkgTypeLibrary},
			reportProvided: false,
			expectError:    true,
			errorMessage:   "library package types require a scanner report file to be provided",
		},
		{
			name:           "Mixed package types with report - should succeed",
			pkgTypes:       []string{PkgTypeOS, PkgTypeLibrary},
			reportProvided: true,
			expectError:    false,
		},
		{
			name:           "Mixed package types without report - should fail",
			pkgTypes:       []string{PkgTypeOS, PkgTypeLibrary},
			reportProvided: false,
			expectError:    true,
			errorMessage:   "library package types require a scanner report file to be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLibraryPkgTypesRequireReport(tt.pkgTypes, tt.reportProvided)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParsePkgTypes(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []string
		expectError bool
	}{
		{
			name:        "empty string defaults to OS",
			input:       "",
			expected:    []string{PkgTypeOS},
			expectError: false,
		},
		{
			name:        "valid OS type",
			input:       "os",
			expected:    []string{PkgTypeOS},
			expectError: false,
		},
		{
			name:        "valid library type",
			input:       "library",
			expected:    []string{PkgTypeLibrary},
			expectError: false,
		},
		{
			name:        "valid mixed types",
			input:       "os,library",
			expected:    []string{PkgTypeOS, PkgTypeLibrary},
			expectError: false,
		},
		{
			name:        "valid mixed types with spaces",
			input:       " os , library ",
			expected:    []string{PkgTypeOS, PkgTypeLibrary},
			expectError: false,
		},
		{
			name:        "invalid type",
			input:       "invalid",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "mixed valid and invalid types",
			input:       "os,invalid",
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePkgTypes(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
