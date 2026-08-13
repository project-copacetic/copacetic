package osrelease

import (
	"fmt"
	"strings"
	"unicode"
)

// ParseValue decodes one os-release assignment value without evaluating shell
// expansions or other shell syntax.
func ParseValue(value string) (string, error) {
	value = strings.TrimLeftFunc(value, unicode.IsSpace)
	if value == "" {
		return "", nil
	}

	switch value[0] {
	case '\'':
		return parseSingleQuotedValue(value)
	case '"':
		return parseDoubleQuotedValue(value)
	default:
		return parseUnquotedValue(value)
	}
}

func parseSingleQuotedValue(value string) (string, error) {
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

func parseDoubleQuotedValue(value string) (string, error) {
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

func parseUnquotedValue(value string) (string, error) {
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
