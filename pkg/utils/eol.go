package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
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
	apiBaseURL   = "https://endoflife.date/api/v1/products"
	httpClient   = &http.Client{Timeout: 10 * time.Second}
	retryTimeout = 15 * time.Second
)

// SetEOLAPIBaseURL allows configuration of the EOL API base URL.
func SetEOLAPIBaseURL(url string) {
	if url != "" {
		apiBaseURL = strings.TrimSuffix(url, "/")
	}
}

// GetEOLAPIBaseURL returns the current EOL API base URL.
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
	case OSTypeDebian:
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
	case OSTypeUbuntu:
		apiVersion = strings.TrimSpace(strings.ToLower(strings.ReplaceAll(apiVersion, "lts", "")))
		parts := strings.Split(apiVersion, ".")
		if len(parts) >= 2 {
			apiVersion = parts[0] + "." + parts[1]
		}
	case OSTypeAlpine:
		parts := strings.Split(apiVersion, ".")
		if len(parts) >= 2 {
			apiVersion = parts[0] + "." + parts[1]
		}
	case OSTypeCentOS, "rhel", OSTypeRocky, OSTypeAlma:
		parts := strings.Split(apiVersion, ".")
		if len(parts) > 0 {
			apiVersion = parts[0]
		}
	case OSTypeAmazon:
		apiProduct = "amazon-linux"
	case "mariner", OSTypeCBLMariner:
		apiProduct = "cbl-mariner"
		parts := strings.Split(apiVersion, ".")
		if len(parts) > 0 {
			apiVersion = parts[0]
		}
	case OSTypeAzureLinux:
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

	// Configure exponential backoff
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 1 * time.Second
	expBackoff.MaxInterval = 8 * time.Second
	expBackoff.Multiplier = 2.0
	expBackoff.RandomizationFactor = 0 // No jitter for predictable behavior
	expBackoff.Reset()

	var isEOL bool
	var eolDate string
	attempt := 0
	startTime := time.Now()

	// Retry logic for 429 responses using exponential backoff
	operation := func() error {
		attempt++

		resp, err := makeEOLAPIRequest(url)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("failed to call EOL API for %s/%s: %w", apiProduct, apiVersion, err))
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			log.Warnf("EOL Check: OS/Version %s/%s not found in the database (404).", apiProduct, apiVersion)
			isEOL = false
			eolDate = "Not in EOL DB"
			return nil
		}

		// Handle rate limiting (429) with retries
		if resp.StatusCode == http.StatusTooManyRequests {
			elapsed := time.Since(startTime)

			// Check if we've already exceeded the timeout
			if elapsed >= retryTimeout {
				log.Warnf("EOL Check: Rate limited by API for %s/%s (429). Retry timeout exceeded after %v.", apiProduct, apiVersion, elapsed)
				return backoff.Permanent(fmt.Errorf("rate limited by EOL API, retry timeout exceeded"))
			}

			nextBackoff := expBackoff.NextBackOff()
			if nextBackoff == backoff.Stop {
				log.Warnf("EOL Check: Rate limited by API for %s/%s (429). Max retries exceeded.", apiProduct, apiVersion)
				return backoff.Permanent(fmt.Errorf("rate limited by EOL API, max retries exceeded"))
			}

			// Cap the sleep to not exceed the remaining timeout
			remainingTimeout := retryTimeout - elapsed
			if nextBackoff > remainingTimeout {
				nextBackoff = remainingTimeout
			}

			log.Debugf("EOL Check: Rate limited (429) for %s/%s, will retry in %v (attempt %d)", apiProduct, apiVersion, nextBackoff, attempt)
			time.Sleep(nextBackoff)
			return fmt.Errorf("rate limited by EOL API (429)")
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return backoff.Permanent(fmt.Errorf("EOL API for %s/%s returned non-OK status: %d - %s", apiProduct, apiVersion, resp.StatusCode, string(bodyBytes)))
		}

		// Success case - parse the response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("failed to read EOL API response body for %s/%s: %w", apiProduct, apiVersion, err))
		}

		var apiResp EOLAPIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			log.Debugf("EOL Check: Failed to unmarshal API response for %s/%s. Body: %s. Error: %v", apiProduct, apiVersion, string(body), err)
			return backoff.Permanent(fmt.Errorf("failed to unmarshal EOL API response for %s/%s: %w", apiProduct, apiVersion, err))
		}
		releaseData := apiResp.Result

		log.Debugf("EOL: API Response for %s/%s - IsEOL: %t, EOLDate: '%s', IsMaintained: %t",
			apiProduct, apiVersion, releaseData.IsEOL, releaseData.EOLDate, releaseData.IsMaintained)

		isEOL = releaseData.IsEOL || !releaseData.IsMaintained
		eolDate = releaseData.EOLDate
		if eolDate == "" || strings.EqualFold(eolDate, "null") {
			eolDate = "Unknown"
		}

		return nil
	}

	// Simple retry loop - backoff.Retry doesn't work well with our manual sleep
	var err error
	for {
		err = operation()
		if err == nil {
			break
		}
		// Permanent errors should not be retried
		if permanent, ok := err.(*backoff.PermanentError); ok {
			err = permanent.Err
			break
		}
	}

	if err != nil {
		// Check if it's a rate limit timeout
		if strings.Contains(err.Error(), "rate limited") {
			return false, "API Rate Limited", err
		}
		return false, "", err
	}

	return isEOL, eolDate, nil
}

// makeEOLAPIRequest creates and executes an HTTP request to the EOL API.
func makeEOLAPIRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EOL API request: %w", err)
	}
	req.Header.Set("User-Agent", "copacetic")

	return httpClient.Do(req)
}
