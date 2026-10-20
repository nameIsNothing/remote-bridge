package diagnostic

import (
	"encoding/xml"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	privateKeyPattern     = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	publicKeyPattern      = regexp.MustCompile(`(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-[A-Za-z0-9-]+)\s+[A-Za-z0-9+/=]{20,}`)
	bearerPattern         = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	credentialURLPattern  = regexp.MustCompile(`(?i)(https?://[^\s/:@]+:)[^\s@]+(@)`)
	secretValuePattern    = regexp.MustCompile(`(?i)(["']?(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|api[_-]?key|authorization)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}\r\n]+)`)
	commandPattern        = regexp.MustCompile(`(?i)(["']?(?:command|script)["']?\s*[:=]\s*)[^\r\n]+`)
	encodedCommandPattern = regexp.MustCompile(`(?i)(-EncodedCommand\s+)[A-Za-z0-9+/=]+`)
	psEscapePattern       = regexp.MustCompile(`_x[0-9A-Fa-f]{4}_`)
)

// Sanitize preserves readable errors while filtering common sensitive values.
// The main protection is at call sites: no command/argv/stdout is accepted.
func Sanitize(value string) string {
	return sanitizeDecoded(decodePowerShellError(value))
}

func sanitizeDecoded(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = privateKeyPattern.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	value = publicKeyPattern.ReplaceAllString(value, "[REDACTED PUBLIC KEY]")
	value = bearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = credentialURLPattern.ReplaceAllString(value, "${1}[REDACTED]${2}")
	value = secretValuePattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = commandPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = encodedCommandPattern.ReplaceAllString(value, "${1}[REDACTED]")
	const limit = 8192
	if len(value) > limit {
		cut := limit - len(" [truncated]")
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut] + " [truncated]"
	}
	return value
}

func decodePowerShellError(value string) string {
	if index := strings.Index(value, "#< CLIXML"); index >= 0 {
		prefix := strings.TrimSpace(value[:index])
		body := strings.TrimSpace(value[index+len("#< CLIXML"):])
		decoder := xml.NewDecoder(strings.NewReader(body))
		var errors []string
		valid := true
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				valid = false
				break
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "S" {
				continue
			}
			isError := false
			for _, attr := range start.Attr {
				if attr.Name.Local == "S" && strings.EqualFold(attr.Value, "Error") {
					isError = true
				}
			}
			if isError {
				var text string
				if err := decoder.DecodeElement(&text, &start); err != nil {
					valid = false
					break
				}
				errors = append(errors, text)
			}
		}
		if valid {
			value = strings.TrimSpace(strings.Join(append([]string{prefix}, errors...), "\n"))
		}
	}
	return psEscapePattern.ReplaceAllStringFunc(value, func(escape string) string {
		code, err := strconv.ParseUint(escape[2:6], 16, 16)
		if err != nil {
			return escape
		}
		return string(rune(code))
	})
}
