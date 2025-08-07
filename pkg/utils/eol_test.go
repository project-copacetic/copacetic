package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newEOLAPIMockServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestCheckEOSL(t *testing.T) {
	originalBaseURL := apiBaseURL
	originalHTTPClient := httpClient
	originalRetryTimeout := retryTimeout
	defer func() {
		apiBaseURL = originalBaseURL
		httpClient = originalHTTPClient
		retryTimeout = originalRetryTimeout
	}()

	tests := []struct {
		name              string
		osType            string
		osVersion         string
		mockAPIResponse   interface{}
		mockAPIStatusCode int
		wantIsEOL         bool
		wantEOLDate       string
		expectError       bool
	}{
		{
			name:      "EOL (Debian Stretch)",
			osType:    "debian",
			osVersion: "stretch",
			mockAPIResponse: EOLAPIResponse{
				Result: EOLProductInfo{IsEOL: true, EOLDate: "2022-06-30", IsMaintained: false},
			},
			mockAPIStatusCode: http.StatusOK,
			wantIsEOL:         true,
			wantEOLDate:       "2022-06-30",
			expectError:       false,
		},
		{
			name:      "Non-EOL (Debian Bullseye)",
			osType:    "debian",
			osVersion: "11",
			mockAPIResponse: EOLAPIResponse{
				Result: EOLProductInfo{IsEOL: false, EOLDate: "2026-07-01", IsMaintained: true},
			},
			mockAPIStatusCode: http.StatusOK,
			wantIsEOL:         false,
			wantEOLDate:       "2026-07-01",
			expectError:       false,
		},
		{
			name:              "OS Not Found in API",
			osType:            "cbl-mariner",
			osVersion:         "5.0",
			mockAPIResponse:   nil,
			mockAPIStatusCode: http.StatusNotFound,
			wantIsEOL:         false,
			wantEOLDate:       "Not in EOL DB",
			expectError:       false,
		},
		{
			name:              "API Rate Limited - No Retry (Short Timeout)",
			osType:            "ubuntu",
			osVersion:         "22.04",
			mockAPIResponse:   nil,
			mockAPIStatusCode: http.StatusTooManyRequests,
			wantIsEOL:         false,
			wantEOLDate:       "API Rate Limited",
			expectError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newEOLAPIMockServer(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.mockAPIStatusCode)
				if tt.mockAPIStatusCode == http.StatusOK && tt.mockAPIResponse != nil {
					if eolResp, ok := tt.mockAPIResponse.(EOLAPIResponse); ok {
						err := json.NewEncoder(w).Encode(eolResp)
						if err != nil {
							_ = err
						}
					}
				}
			})
			defer server.Close()

			apiBaseURL = strings.TrimSuffix(server.URL, "/")
			httpClient = server.Client()
			
			// Set a short retry timeout for rate limit tests
			if strings.Contains(tt.name, "Rate Limited") {
				retryTimeout = 50 * time.Millisecond
			}

			gotIsEOL, gotEOLDate, err := CheckEOSL(tt.osType, tt.osVersion)

			if tt.expectError {
				if err == nil {
					t.Errorf("CheckEOSL() with osType=%s, osVersion=%s: error = nil, want an error", tt.osType, tt.osVersion)
				}
			} else if err != nil {
				t.Errorf("CheckEOSL() with osType=%s, osVersion=%s: unexpected error = %v", tt.osType, tt.osVersion, err)
			}

			if gotIsEOL != tt.wantIsEOL {
				t.Errorf("CheckEOSL() with osType=%s, osVersion=%s: gotIsEOL = %v, want %v", tt.osType, tt.osVersion, gotIsEOL, tt.wantIsEOL)
			}
			if gotEOLDate != tt.wantEOLDate {
				t.Errorf("CheckEOSL() with osType=%s, osVersion=%s: gotEOLDate = '%s', want '%s'", tt.osType, tt.osVersion, gotEOLDate, tt.wantEOLDate)
			}
		})
	}
}

func TestNormalizeOSIdentifierForAPI(t *testing.T) {
	tests := []struct {
		osType             string
		osVersion          string
		expectedAPIProduct string
		expectedAPIVersion string
	}{
		{"debian", "stretch", "debian", "9"},
		{"ubuntu", "20.04 LTS", "ubuntu", "20.04"},
		{"alpine", "3.18.1", "alpine", "3.18"},
		{"cbl-mariner", "2.0", "cbl-mariner", "2"},
	}
	for _, tt := range tests {
		t.Run(tt.osType+"_"+tt.osVersion, func(t *testing.T) {
			gotProduct, gotVersion := normalizeOSIdentifier(tt.osType, tt.osVersion)
			if gotProduct != tt.expectedAPIProduct {
				t.Errorf("normalizeOSIdentifierForAPI() product: got %v, want %v", gotProduct, tt.expectedAPIProduct)
			}
			if gotVersion != tt.expectedAPIVersion {
				t.Errorf("normalizeOSIdentifierForAPI() version: got %v, want %v", gotVersion, tt.expectedAPIVersion)
			}
		})
	}
}

func TestRetryOn429(t *testing.T) {
	originalBaseURL := apiBaseURL
	originalHTTPClient := httpClient
	originalRetryTimeout := retryTimeout
	defer func() {
		apiBaseURL = originalBaseURL
		httpClient = originalHTTPClient
		retryTimeout = originalRetryTimeout
	}()

	// Set a longer retry timeout for this test
	retryTimeout = 3 * time.Second

	var requestCount int64
	server := newEOLAPIMockServer(func(w http.ResponseWriter, _ *http.Request) {
		count := atomic.AddInt64(&requestCount, 1)
		if count <= 2 {
			// First two requests return 429
			w.WriteHeader(http.StatusTooManyRequests)
		} else {
			// Third request succeeds
			w.WriteHeader(http.StatusOK)
			response := EOLAPIResponse{
				Result: EOLProductInfo{IsEOL: false, EOLDate: "2026-07-01", IsMaintained: true},
			}
			_ = json.NewEncoder(w).Encode(response)
		}
	})
	defer server.Close()

	apiBaseURL = strings.TrimSuffix(server.URL, "/")
	httpClient = server.Client()

	start := time.Now()
	isEOL, eolDate, err := CheckEOSL("debian", "11")
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("CheckEOSL() with retry: unexpected error = %v", err)
	}
	if isEOL != false {
		t.Errorf("CheckEOSL() with retry: gotIsEOL = %v, want false", isEOL)
	}
	if eolDate != "2026-07-01" {
		t.Errorf("CheckEOSL() with retry: gotEOLDate = '%s', want '2026-07-01'", eolDate)
	}
	if atomic.LoadInt64(&requestCount) != 3 {
		t.Errorf("Expected 3 requests, got %d", atomic.LoadInt64(&requestCount))
	}
	// Should have taken at least 1s + 2s = 3s for the backoff
	if elapsed < 3*time.Second {
		t.Errorf("Expected at least 3s for retry backoff, got %v", elapsed)
	}
}

func TestRetryTimeoutExceeded(t *testing.T) {
	originalBaseURL := apiBaseURL
	originalHTTPClient := httpClient
	originalRetryTimeout := retryTimeout
	defer func() {
		apiBaseURL = originalBaseURL
		httpClient = originalHTTPClient
		retryTimeout = originalRetryTimeout
	}()

	// Set a very short retry timeout
	retryTimeout = 100 * time.Millisecond

	var requestCount int64
	server := newEOLAPIMockServer(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		// Always return 429
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer server.Close()

	apiBaseURL = strings.TrimSuffix(server.URL, "/")
	httpClient = server.Client()

	start := time.Now()
	isEOL, eolDate, err := CheckEOSL("debian", "11")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("CheckEOSL() with timeout: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "retry timeout exceeded") {
		t.Errorf("CheckEOSL() with timeout: expected 'retry timeout exceeded' error, got %v", err)
	}
	if isEOL != false {
		t.Errorf("CheckEOSL() with timeout: gotIsEOL = %v, want false", isEOL)
	}
	if eolDate != "API Rate Limited" {
		t.Errorf("CheckEOSL() with timeout: gotEOLDate = '%s', want 'API Rate Limited'", eolDate)
	}
	// Should have completed within retry timeout + some buffer
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected completion within 500ms, got %v", elapsed)
	}
	// Should have made at least one request
	if atomic.LoadInt64(&requestCount) < 1 {
		t.Errorf("Expected at least 1 request, got %d", atomic.LoadInt64(&requestCount))
	}
}

func TestSetEOLAPIBaseURL(t *testing.T) {
	originalBaseURL := apiBaseURL
	defer func() {
		apiBaseURL = originalBaseURL
	}()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal URL",
			input:    "https://example.com/api/v1/products",
			expected: "https://example.com/api/v1/products",
		},
		{
			name:     "URL with trailing slash",
			input:    "https://example.com/api/v1/products/",
			expected: "https://example.com/api/v1/products",
		},
		{
			name:     "Empty URL",
			input:    "",
			expected: originalBaseURL, // Should not change
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to original before each test
			apiBaseURL = originalBaseURL
			SetEOLAPIBaseURL(tt.input)
			got := GetEOLAPIBaseURL()
			if got != tt.expected {
				t.Errorf("SetEOLAPIBaseURL(%s): got %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}
