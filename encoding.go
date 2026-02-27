package gohttpsig

import (
	"net/url"
	"sort"
	"strings"
)

// isURIUnreserved returns true if the byte is an unreserved character according to RFC 3986
// Unreserved characters: A-Z a-z 0-9 - _ . ~
func isURIUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' ||
		c == '_' ||
		c == '.' ||
		c == '~'
}

// EncodeURI encodes a URI path according to RFC 3986 for AWS Signature Version 4
// If encodeSlash is true, forward slashes (/) are also encoded
// All characters except unreserved characters (A-Z a-z 0-9 - _ . ~) are percent-encoded
func EncodeURI(path string, encodeSlash bool) string {
	if path == "" {
		return "/"
	}

	var encoded strings.Builder
	encoded.Grow(len(path) * 2) // Pre-allocate to reduce allocations

	for i := 0; i < len(path); i++ {
		c := path[i]

		if isURIUnreserved(c) {
			// Unreserved character - don't encode
			encoded.WriteByte(c)
		} else if c == '/' && !encodeSlash {
			// Forward slash - don't encode unless explicitly requested
			encoded.WriteByte(c)
		} else {
			// All other characters must be percent-encoded with uppercase hex
			encoded.WriteByte('%')
			encoded.WriteByte(uppercaseHex(c >> 4))
			encoded.WriteByte(uppercaseHex(c & 0x0F))
		}
	}

	return encoded.String()
}

// uppercaseHex returns the uppercase hexadecimal character for a 4-bit value
func uppercaseHex(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'A' + b - 10
}

// EncodeQueryValue encodes a single query parameter value according to RFC 3986
// This is used for canonical query string construction
func EncodeQueryValue(value string) string {
	var encoded strings.Builder
	encoded.Grow(len(value) * 2)

	for i := 0; i < len(value); i++ {
		c := value[i]

		if isURIUnreserved(c) {
			encoded.WriteByte(c)
		} else {
			// Percent-encode with uppercase hex
			encoded.WriteByte('%')
			encoded.WriteByte(uppercaseHex(c >> 4))
			encoded.WriteByte(uppercaseHex(c & 0x0F))
		}
	}

	return encoded.String()
}

// EncodeQueryValues encodes URL query parameters into a canonical query string
// The query string is sorted by parameter name, then by value if there are multiple values
// Each parameter is encoded as name=value with proper RFC 3986 encoding
// Multiple parameters are joined with &
func EncodeQueryValues(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	// Create a sorted list of keys
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Build the canonical query string
	var parts []string
	for _, key := range keys {
		encodedKey := EncodeQueryValue(key)
		vals := values[key]

		// Sort values for this key
		sortedVals := make([]string, len(vals))
		copy(sortedVals, vals)
		sort.Strings(sortedVals)

		// Add each key=value pair
		for _, val := range sortedVals {
			encodedVal := EncodeQueryValue(val)
			parts = append(parts, encodedKey+"="+encodedVal)
		}
	}

	return strings.Join(parts, "&")
}

// NormalizePath normalizes a URI path for canonical request construction
// It removes redundant slashes and applies RFC 3986 encoding
func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}

	// Remove redundant slashes
	segments := strings.Split(path, "/")
	normalized := make([]string, 0, len(segments))

	for _, segment := range segments {
		if segment != "" {
			normalized = append(normalized, segment)
		}
	}

	// Rebuild path with single slashes
	result := "/" + strings.Join(normalized, "/")

	// Preserve trailing slash if original had one
	if path != "/" && strings.HasSuffix(path, "/") && !strings.HasSuffix(result, "/") {
		result += "/"
	}

	return result
}
