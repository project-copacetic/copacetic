package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		line := strings.TrimLeftFunc(strings.TrimSuffix(string(rawLine), "\r"), unicode.IsSpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validOSReleaseKey(key) {
			return nil, fmt.Errorf("invalid assignment on line %d", lineNumber+1)
		}
		value, err := parseOSReleaseValue(rawValue)
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
	value = strings.TrimLeftFunc(value, unicode.IsSpace)
	if value == "" {
		return "", nil
	}

	switch value[0] {
	case '\'':
		return parseSingleQuotedOSReleaseValue(value)
	case '"':
		return parseDoubleQuotedOSReleaseValue(value)
	default:
		return parseUnquotedOSReleaseValue(value)
	}
}

func parseSingleQuotedOSReleaseValue(value string) (string, error) {
	closingQuote := strings.IndexByte(value[1:], '\'')
	if closingQuote < 0 {
		return "", fmt.Errorf("unterminated single-quoted value")
	}
	closingQuote++
	if strings.TrimSpace(value[closingQuote+1:]) != "" {
		return "", fmt.Errorf("quoted value has trailing characters; concatenation is not supported")
	}
	return value[1:closingQuote], nil
}

func parseDoubleQuotedOSReleaseValue(value string) (string, error) {
	var parsed strings.Builder
	parsed.Grow(len(value))

	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '"':
			if strings.TrimSpace(value[i+1:]) != "" {
				return "", fmt.Errorf("quoted value has trailing characters; concatenation is not supported")
			}
			return parsed.String(), nil
		case '\\':
			if i+1 >= len(value) {
				return "", fmt.Errorf("unterminated escape in double-quoted value")
			}
			i++
			switch value[i] {
			case '$', '`', '"', '\\':
				parsed.WriteByte(value[i])
			default:
				// In double quotes, Bourne-shell escaping removes the backslash
				// only before $, `, ", and \\; otherwise it remains literal.
				parsed.WriteByte('\\')
				parsed.WriteByte(value[i])
			}
		case '$', '`':
			return "", fmt.Errorf("unescaped shell expansion character %q", value[i])
		default:
			parsed.WriteByte(value[i])
		}
	}

	return "", fmt.Errorf("unterminated double-quoted value")
}

func parseUnquotedOSReleaseValue(value string) (string, error) {
	var parsed strings.Builder
	parsed.Grow(len(value))
	escaped := false

	for offset, r := range value {
		if escaped {
			parsed.WriteRune(r)
			escaped = false
			continue
		}

		switch r {
		case '\\':
			escaped = true
		case '\'', '"':
			return "", fmt.Errorf("quote in unquoted value; quote the entire value")
		case '$', '`':
			return "", fmt.Errorf("unescaped shell expansion character %q", r)
		case ';', '&', '|', '(', ')', '<', '>':
			return "", fmt.Errorf("unescaped shell control character %q", r)
		default:
			if unicode.IsSpace(r) {
				if strings.TrimSpace(value[offset:]) == "" {
					return parsed.String(), nil
				}
				return "", fmt.Errorf("unquoted value contains unescaped whitespace")
			}
			parsed.WriteRune(r)
		}
	}

	if escaped {
		return "", fmt.Errorf("unterminated escape in unquoted value")
	}
	return parsed.String(), nil
}
