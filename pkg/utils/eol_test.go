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

func TestIsNumericPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Empty string", "", false},
		{"Numeric prefix", "1.0", true},
		{"Numeric single digit", "9", true},
		{"Non-numeric prefix", "stretch", false},
		{"Non-numeric prefix with number", "ubuntu20.04", false},
		{"Leading zero", "0.1", true},
		{"Leading space", " 1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNumericPrefix(tt.input)
			if result != tt.expected {
				t.Errorf("isNumericPrefix(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeOSIdentifierComprehensive(t *testing.T) {
	tests := []struct {
		name               string
		osType             string
		osVersion          string
		expectedAPIProduct string
		expectedAPIVersion string
	}{
		// Debian codename tests
		{"Debian buzz", "debian", "buzz", "debian", "1"},
		{"Debian rex", "debian", "rex", "debian", "1"},
		{"Debian bo", "debian", "bo", "debian", "1"},
		{"Debian hamm", "debian", "hamm", "debian", "2"},
		{"Debian slink", "debian", "slink", "debian", "2"},
		{"Debian potato", "debian", "potato", "debian", "2"},
		{"Debian woody", "debian", "woody", "debian", "3"},
		{"Debian sarge", "debian", "sarge", "debian", "3"},
		{"Debian etch", "debian", "etch", "debian", "4"},
		{"Debian lenny", "debian", "lenny", "debian", "5"},
		{"Debian squeeze", "debian", "squeeze", "debian", "6"},
		{"Debian wheezy", "debian", "wheezy", "debian", "7"},
		{"Debian jessie", "debian", "jessie", "debian", "8"},
		{"Debian stretch", "debian", "stretch", "debian", "9"},
		{"Debian buster", "debian", "buster", "debian", "10"},
		{"Debian bullseye", "debian", "bullseye", "debian", "11"},
		{"Debian bookworm", "debian", "bookworm", "debian", "12"},
		{"Debian trixie", "debian", "trixie", "debian", "13"},
		{"Debian forky", "debian", "forky", "debian", "14"},
		{"Debian unknown codename", "debian", "unknown", "debian", "unknown"},

		// Debian numeric version tests
		{"Debian numeric version", "debian", "11.5", "debian", "11"},
		{"Debian numeric single", "debian", "10", "debian", "10"},

		// Ubuntu tests
		{"Ubuntu LTS uppercase", "ubuntu", "20.04 LTS", "ubuntu", "20.04"},
		{"Ubuntu LTS lowercase", "ubuntu", "18.04 lts", "ubuntu", "18.04"},
		{"Ubuntu no LTS", "ubuntu", "21.10", "ubuntu", "21.10"},
		{"Ubuntu three parts", "ubuntu", "20.04.3", "ubuntu", "20.04"},
		{"Ubuntu single part", "ubuntu", "20", "ubuntu", "20"},

		// Alpine tests
		{"Alpine two parts", "alpine", "3.18", "alpine", "3.18"},
		{"Alpine three parts", "alpine", "3.18.1", "alpine", "3.18"},
		{"Alpine single part", "alpine", "3", "alpine", "3"},

		// CentOS/RHEL/Rocky/Alma tests
		{"CentOS with decimal", "centos", "8.4", "centos", "8"},
		{"RHEL single digit", "rhel", "9", "rhel", "9"},
		{"Rocky Linux", "rocky", "8.5", "rocky", "8"},
		{"Alma Linux", "alma", "9.1", "alma", "9"},

		// Amazon Linux tests
		{"Amazon Linux", "amazon", "2", "amazon-linux", "2"},
		{"Amazon Linux version", "amazon", "2023", "amazon-linux", "2023"},

		// Mariner/CBL-Mariner tests
		{"Mariner", "mariner", "2.0", "cbl-mariner", "2"},
		{"CBL-Mariner", "cbl-mariner", "1.0", "cbl-mariner", "1"},

		// Azure Linux tests
		{"Azure Linux", "azurelinux", "3.0", "azure-linux", "3"},
		{"Azure Linux no decimal", "azurelinux", "2", "azure-linux", "2"},

		// Case sensitivity tests
		{"Uppercase OS type", "DEBIAN", "STRETCH", "debian", "9"},
		{"Mixed case", "Ubuntu", "20.04 LTS", "ubuntu", "20.04"},

		// Unknown OS type
		{"Unknown OS", "unknown", "1.0", "unknown", "1.0"},
		{"Custom OS", "customos", "v2.1", "customos", "v2.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProduct, gotVersion := normalizeOSIdentifier(tt.osType, tt.osVersion)
			if gotProduct != tt.expectedAPIProduct {
				t.Errorf("normalizeOSIdentifier(%q, %q) product: got %v, want %v",
					tt.osType, tt.osVersion, gotProduct, tt.expectedAPIProduct)
			}
			if gotVersion != tt.expectedAPIVersion {
				t.Errorf("normalizeOSIdentifier(%q, %q) version: got %v, want %v",
					tt.osType, tt.osVersion, gotVersion, tt.expectedAPIVersion)
			}
		})
	}
}
