package gohttpsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

const (
	// Algorithm is the AWS Signature Version 4 algorithm identifier
	Algorithm = "AWS4-HMAC-SHA256"

	// TimeFormat is the ISO8601 basic format used for timestamps
	TimeFormat = "20060102T150405Z"

	// DateFormat is the date format used for credential scope
	DateFormat = "20060102"

	// AWS4Request is the termination string for the credential scope
	AWS4Request = "aws4_request"

	// UnsignedPayload is used when the payload is not signed
	UnsignedPayload = "UNSIGNED-PAYLOAD"
)

// DeriveSigningKey derives the signing key using the AWS Signature Version 4 algorithm
// This performs a 4-step HMAC-SHA256 chain:
// 1. kDate = HMAC-SHA256("AWS4" + secret, date)
// 2. kRegion = HMAC-SHA256(kDate, region)
// 3. kService = HMAC-SHA256(kRegion, service)
// 4. kSigning = HMAC-SHA256(kService, "aws4_request")
func DeriveSigningKey(secret, date, region, service string) []byte {
	// Step 1: HMAC-SHA256("AWS4" + secret, date)
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))

	// Step 2: HMAC-SHA256(kDate, region)
	kRegion := hmacSHA256(kDate, []byte(region))

	// Step 3: HMAC-SHA256(kRegion, service)
	kService := hmacSHA256(kRegion, []byte(service))

	// Step 4: HMAC-SHA256(kService, "aws4_request")
	kSigning := hmacSHA256(kService, []byte(AWS4Request))

	return kSigning
}

// hmacSHA256 computes HMAC-SHA256 of data using the provided key
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ComputeSignature computes the signature for the given string to sign
// using the provided signing key. Returns the signature as a lowercase hex string.
func ComputeSignature(signingKey []byte, stringToSign string) string {
	signature := hmacSHA256(signingKey, []byte(stringToSign))
	return hex.EncodeToString(signature)
}

// ComputePayloadHash computes the SHA256 hash of the request payload
// and returns it as a lowercase hex string
func ComputePayloadHash(payload io.Reader) (string, error) {
	if payload == nil {
		return UnsignedPayload, nil
	}

	h := sha256.New()
	if _, err := io.Copy(h, payload); err != nil {
		return "", fmt.Errorf("failed to compute payload hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputePayloadHashFromBytes computes the SHA256 hash of the request payload bytes
// and returns it as a lowercase hex string
func ComputePayloadHashFromBytes(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// ComputeStringHash computes the SHA256 hash of a string
// and returns it as a lowercase hex string
func ComputeStringHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// FormatSigningTime formats a time value into the ISO8601 basic format
// used in AWS Signature Version 4: YYYYMMDDTHHMMSSZ
func FormatSigningTime(t time.Time) string {
	return t.UTC().Format(TimeFormat)
}

// FormatSigningDate formats a time value into the date format
// used in the credential scope: YYYYMMDD
func FormatSigningDate(t time.Time) string {
	return t.UTC().Format(DateFormat)
}

// ParseSigningTime parses a timestamp in ISO8601 basic format
func ParseSigningTime(timestamp string) (time.Time, error) {
	return time.Parse(TimeFormat, timestamp)
}

// VerifySignature performs constant-time comparison of two signatures
// to prevent timing attacks
func VerifySignature(expected, actual string) bool {
	expectedBytes := []byte(expected)
	actualBytes := []byte(actual)

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(expectedBytes, actualBytes) == 1
}

// BuildCredentialScope builds the credential scope string
// Format: YYYYMMDD/region/service/aws4_request
func BuildCredentialScope(date, region, service string) string {
	return fmt.Sprintf("%s/%s/%s/%s", date, region, service, AWS4Request)
}

// ParseCredentialScope parses a credential scope string into its components
// Returns date, region, service, and an error if parsing fails
func ParseCredentialScope(scope string) (date, region, service string, err error) {
	parts := splitCredentialScope(scope)
	if len(parts) != 4 {
		return "", "", "", fmt.Errorf("invalid credential scope format: expected 4 parts, got %d", len(parts))
	}

	if parts[3] != AWS4Request {
		return "", "", "", fmt.Errorf("invalid credential scope: expected terminator %q, got %q", AWS4Request, parts[3])
	}

	return parts[0], parts[1], parts[2], nil
}

// splitCredentialScope splits a credential scope by '/' delimiter
func splitCredentialScope(scope string) []string {
	var parts []string
	start := 0

	for i := 0; i < len(scope); i++ {
		if scope[i] == '/' {
			parts = append(parts, scope[start:i])
			start = i + 1
		}
	}

	// Add the last part
	if start < len(scope) {
		parts = append(parts, scope[start:])
	}

	return parts
}
