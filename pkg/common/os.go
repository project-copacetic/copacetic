package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/project-copacetic/copacetic/internal/osrelease"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// os-release files are normally only a few kilobytes. Cap image-controlled
// input before parsing so malformed files cannot amplify memory use.
const maxOSReleaseSize = 1 << 20

// OSInfo contains the OS type and version information.
type OSInfo struct {
	Type    string
	Version string
}

// GetOSInfo extracts OS type and version from os-release data.
func GetOSInfo(ctx context.Context, osreleaseBytes []byte) (*OSInfo, error) {
	osData, err := parseOSRelease(ctx, osreleaseBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse os-release data: %w", err)
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

func parseOSRelease(ctx context.Context, data []byte) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > maxOSReleaseSize {
		return nil, fmt.Errorf("os-release exceeds %d-byte limit", maxOSReleaseSize)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("os-release contains invalid UTF-8")
	}

	values := make(map[string]string)
	for lineNumber := 1; len(data) > 0; lineNumber++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		var rawLine []byte
		if newline := bytes.IndexByte(data, '\n'); newline >= 0 {
			rawLine, data = data[:newline], data[newline+1:]
		} else {
			rawLine, data = data, nil
		}

		line := strings.TrimSuffix(string(rawLine), "\r")
		if err := validateOSReleaseText(line, true); err != nil {
			return nil, fmt.Errorf("invalid content on line %d: %w", lineNumber, err)
		}
		line = strings.TrimLeftFunc(line, unicode.IsSpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validOSReleaseKey(key) {
			return nil, fmt.Errorf("invalid assignment on line %d", lineNumber)
		}
		value, err := parseOSReleaseValue(rawValue)
		if err != nil {
			return nil, fmt.Errorf("invalid value for %s on line %d: %w", key, lineNumber, err)
		}
		values[key] = value
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("os-release contains no assignments")
	}
	return values, nil
}

func validOSReleaseKey(key string) bool {
	if key == "" || !isASCIIOSReleaseKeyStart(key[0]) {
		return false
	}
	for i := 1; i < len(key); i++ {
		if !isASCIIOSReleaseKeyCharacter(key[i]) {
			return false
		}
	}
	return true
}

func isASCIIOSReleaseKeyStart(character byte) bool {
	return character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
}

func isASCIIOSReleaseKeyCharacter(character byte) bool {
	return isASCIIOSReleaseKeyStart(character) || character >= '0' && character <= '9'
}

func parseOSReleaseValue(value string) (string, error) {
	if err := validateOSReleaseText(value, true); err != nil {
		return "", err
	}
	parsed, err := osrelease.ParseValue(value)
	if err != nil {
		return "", err
	}
	if err := validateOSReleaseText(parsed, false); err != nil {
		return "", err
	}
	return parsed, nil
}

func validateOSReleaseText(value string, allowHorizontalTab bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("value contains invalid UTF-8")
	}
	for _, character := range value {
		if allowHorizontalTab && character == '\t' {
			continue
		}
		if !unicode.IsGraphic(character) {
			return fmt.Errorf("value contains non-printable character %U", character)
		}
	}
	return nil
}
