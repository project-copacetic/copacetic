package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

// FuzzTrivyParser tests the Trivy parser with random JSON input
func FuzzTrivyParser(f *testing.F) {
	// Add seed corpus from existing test data
	if data, err := os.ReadFile("testdata/trivy_valid.json"); err == nil {
		f.Add(data)
	}

	// Add some additional seed cases that are more realistic
	validMinimal := `{"SchemaVersion": 2, "Metadata": {"OS": {"Family": "alpine", "Name": "3.14"}, "ImageConfig": {"Architecture": "amd64"}}, "Results": [{"Class": "os-pkgs", "Vulnerabilities": []}]}`
	f.Add([]byte(validMinimal))
	f.Add([]byte(`{"SchemaVersion": 2, "Results": []}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create temporary file for the fuzz input
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "fuzz_input.json")
		
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			t.Skip("Failed to write temp file")
		}

		parser := &TrivyParser{}
		
		// The parser should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("TrivyParser.Parse panicked: %v", r)
			}
		}()

		// Parse should either succeed or return an error, but not panic
		_, err := parser.Parse(tmpFile)
		
		// We don't assert anything about the error since fuzzing
		// is meant to find crashes, not validate correctness
		_ = err
	})
}

// FuzzParseTrivyReport tests the low-level Trivy report parsing
func FuzzParseTrivyReport(f *testing.F) {
	// Add seed corpus
	if data, err := os.ReadFile("testdata/trivy_valid.json"); err == nil {
		f.Add(data)
	}

	// Add minimal valid JSON structures
	f.Add([]byte(`{"SchemaVersion": 2}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create temporary file
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "fuzz_input.json")
		
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			t.Skip("Failed to write temp file")
		}

		// Should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseTrivyReport panicked: %v", r)
			}
		}()

		_, err := parseTrivyReport(tmpFile)
		_ = err // Ignore error, just ensure no panic
	})
}

// FuzzCustomParseScanReport tests custom scanner report parsing
func FuzzCustomParseScanReport(f *testing.F) {
	// Add seed cases for v1alpha1 format
	f.Add([]byte(`{"apiVersion": "v1alpha1", "metadata": {}}`))
	f.Add([]byte(`{"apiVersion": "unknown", "data": "test"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create temporary file
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "fuzz_input.json")
		
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			t.Skip("Failed to write temp file")
		}

		// Should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("customParseScanReport panicked: %v", r)
			}
		}()

		// Test with "native" scanner to trigger direct file reading
		_, err := customParseScanReport(tmpFile, "native")
		_ = err // Ignore error, just ensure no panic
	})
}

// FuzzJSONUnmarshal tests JSON unmarshaling with random data
func FuzzJSONUnmarshal(f *testing.F) {
	// Add various JSON structures that might be encountered
	f.Add([]byte(`{"apiVersion": "v1alpha1"}`))
	f.Add([]byte(`{"SchemaVersion": 2}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`true`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test unmarshaling into various types that are used in the codebase
		
		// Test generic map unmarshaling (used in convertToUnversionedAPI)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON unmarshal into map panicked: %v", r)
			}
		}()

		var m map[string]interface{}
		_ = json.Unmarshal(data, &m)

		// Test Trivy report unmarshaling
		var trivyReport trivyTypes.Report
		_ = json.Unmarshal(data, &trivyReport)
	})
}