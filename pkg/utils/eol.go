package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type EOLProductInfo struct {
	IsEOL        bool   `json:"isEol"`
	EOLDate      string `json:"eolFrom"`
	IsMaintained bool   `json:"isMaintained"`
}

type EOLAPIResponse struct {
	SchemaVersion string         `json:"schema_version"`
	GeneratedAt   string         `json:"generated_at"`
	Result        EOLProductInfo `json:"result"`
}

var (
	apiBaseURL = "https://endoflife.date/api/v1/products"
	httpClient = &http.Client{Timeout: 10 * time.Second}
	retryTimeout = 15 * time.Second
)

// SetEOLAPIBaseURL allows configuration of the EOL API base URL
func SetEOLAPIBaseURL(url string) {
	if url != "" {
		apiBaseURL = strings.TrimSuffix(url, "/")
	}
}

// GetEOLAPIBaseURL returns the current EOL API base URL
func GetEOLAPIBaseURL() string {
	return apiBaseURL
}

func isNumericPrefix(s string) bool {
	if s == "" {
		return false
	}
	return s[0] >= '0' && s[0] <= '9'
}

func normalizeOSIdentifier(osType, osVersion string) (apiProduct string, apiVersion string) {
	apiProduct = strings.ToLower(osType)
	apiVersion = strings.ToLower(osVersion)

	switch apiProduct {
	case "debian":
		if !isNumericPrefix(apiVersion) {
			switch apiVersion {
			case "buzz", "rex", "bo":
				apiVersion = "1"
			case "hamm", "slink", "potato":
				apiVersion = "2"
			case "woody", "sarge":
				apiVersion = "3"
			case "etch":
				apiVersion = "4"
			case "lenny":
				apiVersion = "5"
			case "squeeze":
				apiVersion = "6"
			case "wheezy":
				apiVersion = "7"
			case "jessie":
				apiVersion = "8"
			case "stretch":
				apiVersion = "9"
			case "buster":
				apiVersion = "10"
			case "bullseye":
				apiVersion = "11"
			case "bookworm":
				apiVersion = "12"
			case "trixie":
				apiVersion = "13"
			case "forky":
				apiVersion = "14"
			default:
				log.Debugf("EOL Check: Unmapped Debian codename '%s'. Using as is for API path.", osVersion)
			}
		} else {
			parts := strings.Split(apiVersion, ".")
			if len(parts) > 0 {
				apiVersion = parts[0]
			}
		}
	case "ubuntu":
		apiVersion = strings.TrimSpace(strings.ToLower(strings.ReplaceAll(apiVersion, "lts", "")))
		parts := strings.Split(apiVersion, ".")
		if len(parts) >= 2 {
			apiVersion = parts[0] + "." + parts[1]
		}
	case "alpine":
		parts := strings.Split(apiVersion, ".")
		if len(parts) >= 2 {
			apiVersion = parts[0] + "." + parts[1]
		}
	case "centos", "rhel", "rocky", "alma":
		parts := strings.Split(apiVersion, ".")
		if len(parts) > 0 {
			apiVersion = parts[0]
		}
	case "amazon":
		apiProduct = "amazon-linux"
	case "mariner", "cbl-mariner":
		apiProduct = "cbl-mariner"
		parts := strings.Split(apiVersion, ".")
		if len(parts) > 0 {
			apiVersion = parts[0]
		}
	case "azurelinux":
		apiProduct = "azure-linux"
		parts := strings.Split(apiVersion, ".")
		if len(parts) > 0 {
			apiVersion = parts[0]
		}
	default:
		log.Debugf("EOL Check: OS type '%s' has no specific normalization rules. Using product='%s', version_segment='%s' for API path.", osType, apiProduct, apiVersion)
	}
	return apiProduct, apiVersion
}

func CheckEOSL(osType, osVersion string) (bool, string, error) {
	if osType == "" || osVersion == "" {
		return false, "", fmt.Errorf("internal error: OS type and version must be provided for EOL check")
	}

	apiProduct, apiVersion := normalizeOSIdentifier(osType, osVersion)
	if apiProduct == "" || apiVersion == "" {
		log.Warnf("Could not determine valid API Product and Version for OS '%s %s'. Skipping EOL check.", osType, osVersion)
		return false, "Normalization Failed", nil
	}

	url := fmt.Sprintf("%s/%s/releases/%s", apiBaseURL, apiProduct, apiVersion)
	log.Debugf("EOL Check: Querying URL: %s", url)

	// Retry logic for 429 responses
	startTime := time.Now()
	attempt := 0
	for {
		attempt++
		resp, err := makeEOLAPIRequest(url)
		if err != nil {
			return false, "", fmt.Errorf("failed to call EOL API for %s/%s: %w", apiProduct, apiVersion, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			log.Warnf("EOL Check: OS/Version %s/%s not found in the database (404).", apiProduct, apiVersion)
			return false, "Not in EOL DB", nil
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			elapsed := time.Since(startTime)
			if elapsed >= retryTimeout {
				log.Warnf("EOL Check: Rate limited by API for %s/%s (429). Retry timeout exceeded after %v.", apiProduct, apiVersion, elapsed)
				return false, "API Rate Limited", fmt.Errorf("rate limited by EOL API, retry timeout exceeded")
			}

			// Exponential backoff: 1s, 2s, 4s, 8s...
			backoffDuration := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			// Cap the backoff to avoid very long waits
			if backoffDuration > 8*time.Second {
				backoffDuration = 8 * time.Second
			}
			// Don't wait longer than the remaining timeout
			if elapsed+backoffDuration > retryTimeout {
				backoffDuration = retryTimeout - elapsed
			}

			log.Debugf("EOL Check: Rate limited (429) for %s/%s, retrying in %v (attempt %d)", apiProduct, apiVersion, backoffDuration, attempt)
			time.Sleep(backoffDuration)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return false, "", fmt.Errorf("EOL API for %s/%s returned non-OK status: %d - %s", apiProduct, apiVersion, resp.StatusCode, string(bodyBytes))
		}

		// Success case - parse the response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, "", fmt.Errorf("failed to read EOL API response body for %s/%s: %w", apiProduct, apiVersion, err)
		}

		var apiResp EOLAPIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			log.Debugf("EOL Check: Failed to unmarshal API response for %s/%s. Body: %s. Error: %v", apiProduct, apiVersion, string(body), err)
			return false, "", fmt.Errorf("failed to unmarshal EOL API response for %s/%s: %w", apiProduct, apiVersion, err)
		}
		releaseData := apiResp.Result

		log.Debugf("EOL: API Response for %s/%s - IsEOL: %t, EOLDate: '%s', IsMaintained: %t",
			apiProduct, apiVersion, releaseData.IsEOL, releaseData.EOLDate, releaseData.IsMaintained)

		isEffectivelyEOL := releaseData.IsEOL || !releaseData.IsMaintained
		displayEOLDate := releaseData.EOLDate
		if displayEOLDate == "" || strings.EqualFold(displayEOLDate, "null") {
			displayEOLDate = "Unknown"
		}

		return isEffectivelyEOL, displayEOLDate, nil
	}
}

// makeEOLAPIRequest creates and executes an HTTP request to the EOL API
func makeEOLAPIRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EOL API request: %w", err)
	}
	req.Header.Set("User-Agent", "copacetic")

	return httpClient.Do(req)
}
