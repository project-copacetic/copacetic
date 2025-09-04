package utils

import (
	"encoding/json"
	"testing"
)

// FuzzEOLAPIResponseParsing tests EOL API response JSON parsing
func FuzzEOLAPIResponseParsing(f *testing.F) {
	// Add seed corpus with various EOL API response formats
	f.Add([]byte(`{"schema_version": "1.0", "generated_at": "2023-01-01", "result": {"isEol": true, "eolFrom": "2022-12-31", "isMaintained": false}}`))
	f.Add([]byte(`{"schema_version": "1.0", "result": {"isEol": false, "isMaintained": true}}`))
	f.Add([]byte(`{"result": {}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EOL API response parsing panicked: %v", r)
			}
		}()

		var apiResp EOLAPIResponse
		_ = json.Unmarshal(data, &apiResp)
	})
}

// FuzzPodmanInspectParsing tests podman inspect JSON output parsing
func FuzzPodmanInspectParsing(f *testing.F) {
	// Add seed corpus with various podman inspect output formats
	f.Add([]byte(`[{"Id": "abc123", "MediaType": "application/vnd.docker.distribution.manifest.v2+json", "Digest": "sha256:123"}]`))
	f.Add([]byte(`[{"Id": "abc123"}]`))
	f.Add([]byte(`[{}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Podman inspect parsing panicked: %v", r)
			}
		}()

		var inspectResults []map[string]interface{}
		_ = json.Unmarshal(data, &inspectResults)
	})
}

// FuzzGenericJSONMapParsing tests generic JSON to map parsing used throughout utils
func FuzzGenericJSONMapParsing(f *testing.F) {
	// Add seed corpus with various JSON structures
	f.Add([]byte(`{"key": "value", "number": 123, "boolean": true}`))
	f.Add([]byte(`{"nested": {"key": "value"}}`))
	f.Add([]byte(`{"array": [1, 2, 3]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`true`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Generic JSON map parsing panicked: %v", r)
			}
		}()

		var result map[string]interface{}
		_ = json.Unmarshal(data, &result)

		// Also test slice of maps which is used in podman parsing
		var resultSlice []map[string]interface{}
		_ = json.Unmarshal(data, &resultSlice)
	})
}

// FuzzEOLProductInfoParsing tests EOLProductInfo struct parsing
func FuzzEOLProductInfoParsing(f *testing.F) {
	// Add seed corpus with various EOL product info formats
	f.Add([]byte(`{"isEol": true, "eolFrom": "2022-12-31", "isMaintained": false}`))
	f.Add([]byte(`{"isEol": false, "isMaintained": true}`))
	f.Add([]byte(`{"isEol": "invalid", "eolFrom": null}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EOLProductInfo parsing panicked: %v", r)
			}
		}()

		var productInfo EOLProductInfo
		_ = json.Unmarshal(data, &productInfo)
	})
}

// FuzzStringArrayParsing tests parsing of string arrays from JSON
func FuzzStringArrayParsing(f *testing.F) {
	// Add seed corpus with various string array formats
	f.Add([]byte(`["string1", "string2", "string3"]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[""]`))
	f.Add([]byte(`[null, "string"]`))
	f.Add([]byte(`["string", 123, true]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("String array parsing panicked: %v", r)
			}
		}()

		var stringArray []string
		_ = json.Unmarshal(data, &stringArray)

		// Also test interface{} slice which might be used
		var interfaceArray []interface{}
		_ = json.Unmarshal(data, &interfaceArray)
	})
}