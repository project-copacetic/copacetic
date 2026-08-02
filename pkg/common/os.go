package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// OSInfo contains the OS type and version information.
type OSInfo struct {
	Type    string
	Version string
}

// GetOSInfo extracts OS type and version from os-release data.
func GetOSInfo(_ context.Context, osreleaseBytes []byte) (*OSInfo, error) {
	osData, err := parseOSRelease(osreleaseBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse os-release data %w", err)
	}

	osType := strings.ToLower(osData["NAME"])
	if osType == "" {
		osType = strings.ToLower(osData["ID"])
	}
	normalizedType := utils.CanonicalOSType(osType)
	if normalizedType == "" {
		log.Error("unsupported osType ", osType)
		return nil, errors.ErrUnsupported
	}

	return &OSInfo{
		Type:    normalizedType,
		Version: osData["VERSION_ID"],
	}, nil
}

func parseOSRelease(data []byte) (map[string]string, error) {
	values := make(map[string]string)
	for lineNumber, rawLine := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSpace(strings.TrimSuffix(string(rawLine), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validOSReleaseKey(key) {
			return nil, fmt.Errorf("invalid assignment on line %d", lineNumber+1)
		}
		value, err := parseOSReleaseValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, fmt.Errorf("invalid value for %s on line %d: %w", key, lineNumber+1, err)
		}
		values[key] = value
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("os-release contains no assignments")
	}
	return values, nil
}

func validOSReleaseKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if r == '_' || unicode.IsUpper(r) || (i > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

func parseOSReleaseValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	switch value[0] {
	case '"':
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return parsed, nil
	case '\'':
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		return value[1 : len(value)-1], nil
	default:
		if strings.ContainsFunc(value, unicode.IsSpace) {
			return "", fmt.Errorf("unquoted value contains whitespace")
		}
		return value, nil
	}
}
