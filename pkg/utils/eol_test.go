package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newEOLAPIMockServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestCheckEOSL(t *testing.T) {
	originalBaseURL := apiBaseURL
	originalHTTPClient := httpClient
	defer func() {
		apiBaseURL = originalBaseURL
		httpClient = originalHTTPClient
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
			name:              "API Rate Limited",
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
