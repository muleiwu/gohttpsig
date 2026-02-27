package gohttpsig

import (
	"net/http"
	"sort"
	"strings"
)

const (
	// HeaderHost is the Host header name
	HeaderHost = "host"

	// HeaderAuthorization is the Authorization header name
	HeaderAuthorization = "Authorization"

	// HeaderXAmzDate is the X-Amz-Date header name for the request timestamp
	HeaderXAmzDate = "X-Amz-Date"

	// HeaderXAmzContentSHA256 is the X-Amz-Content-Sha256 header for payload hash
	HeaderXAmzContentSHA256 = "X-Amz-Content-Sha256"

	// HeaderXAmzSecurityToken is the X-Amz-Security-Token header for session tokens
	HeaderXAmzSecurityToken = "X-Amz-Security-Token"

	// HeaderContentType is the Content-Type header
	HeaderContentType = "Content-Type"
)

// CanonicalizeHeaders creates the canonical headers string for AWS Signature Version 4
// It takes the HTTP headers and a list of header names to include in the signature
// Returns the canonical headers string and the signed headers list
//
// Rules:
// 1. Convert header names to lowercase
// 2. Trim leading and trailing whitespace from values
// 3. Convert sequential spaces in values to a single space
// 4. Sort headers by name (case-insensitive)
// 5. Format as "name:value\n" for each header
// 6. The signed headers list is semicolon-separated lowercase header names
func CanonicalizeHeaders(headers http.Header, signedHeaderNames []string) (canonical string, signedHeaders string) {
	if len(signedHeaderNames) == 0 {
		return "", ""
	}

	// Create a map for quick lookup and normalize header names
	headerMap := make(map[string]string)
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		// Join multiple values with comma (as per HTTP spec)
		value := strings.Join(values, ",")
		// Trim and normalize whitespace
		headerMap[lowerKey] = normalizeHeaderValue(value)
	}

	// Sort signed header names
	sortedNames := make([]string, len(signedHeaderNames))
	copy(sortedNames, signedHeaderNames)
	for i, name := range sortedNames {
		sortedNames[i] = strings.ToLower(name)
	}
	sort.Strings(sortedNames)

	// Build canonical headers string
	var builder strings.Builder
	for _, name := range sortedNames {
		value := headerMap[name]
		builder.WriteString(name)
		builder.WriteString(":")
		builder.WriteString(value)
		builder.WriteString("\n")
	}

	canonical = builder.String()
	signedHeaders = strings.Join(sortedNames, ";")

	return canonical, signedHeaders
}

// normalizeHeaderValue trims whitespace and collapses multiple spaces to single space
func normalizeHeaderValue(value string) string {
	// Trim leading and trailing whitespace
	value = strings.TrimSpace(value)

	// Collapse multiple spaces to single space
	var result strings.Builder
	result.Grow(len(value))

	prevSpace := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' || c == '\t' {
			if !prevSpace {
				result.WriteByte(' ')
				prevSpace = true
			}
		} else {
			result.WriteByte(c)
			prevSpace = false
		}
	}

	return result.String()
}

// ExtractSignedHeaders determines which headers should be included in the signature
// By default, includes:
// - host (always required)
// - All x-amz-* headers
// - content-type (if present)
//
// Additional headers can be specified via options
func ExtractSignedHeaders(headers http.Header, additionalHeaders []string) []string {
	signedHeaders := make(map[string]bool)

	// Always include host header
	signedHeaders[HeaderHost] = true

	// Include all x-amz-* headers
	for name := range headers {
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-amz-") {
			signedHeaders[lowerName] = true
		}
	}

	// Include content-type if present
	if headers.Get(HeaderContentType) != "" {
		signedHeaders[strings.ToLower(HeaderContentType)] = true
	}

	// Include any additional headers specified
	for _, name := range additionalHeaders {
		lowerName := strings.ToLower(name)
		if headers.Get(name) != "" {
			signedHeaders[lowerName] = true
		}
	}

	// Convert to sorted slice
	result := make([]string, 0, len(signedHeaders))
	for name := range signedHeaders {
		result = append(result, name)
	}
	sort.Strings(result)

	return result
}

// GetHeaderValue retrieves a header value in a case-insensitive manner
func GetHeaderValue(headers http.Header, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			if len(values) > 0 {
				return values[0]
			}
		}
	}
	return ""
}

// SetHeaderValue sets a header value, replacing any existing values
func SetHeaderValue(headers http.Header, name, value string) {
	headers.Set(name, value)
}
