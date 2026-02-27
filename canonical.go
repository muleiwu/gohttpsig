package gohttpsig

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CanonicalRequest represents a canonical HTTP request for AWS Signature Version 4
type CanonicalRequest struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string

	// CanonicalURI is the RFC 3986 encoded URI path
	CanonicalURI string

	// CanonicalQueryString is the sorted, encoded query parameters
	CanonicalQueryString string

	// CanonicalHeaders is the formatted canonical headers string
	CanonicalHeaders string

	// SignedHeaders is the semicolon-separated list of signed header names
	SignedHeaders string

	// PayloadHash is the SHA256 hash of the payload or "UNSIGNED-PAYLOAD"
	PayloadHash string
}

// String returns the canonical request as a string in the AWS SigV4 format:
// HTTPMethod + "\n" +
// CanonicalURI + "\n" +
// CanonicalQueryString + "\n" +
// CanonicalHeaders + "\n" +
// SignedHeaders + "\n" +
// HashedPayload
func (cr *CanonicalRequest) String() string {
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		cr.Method,
		cr.CanonicalURI,
		cr.CanonicalQueryString,
		cr.CanonicalHeaders,
		cr.SignedHeaders,
		cr.PayloadHash,
	)
}

// StringToSign represents the string that will be signed
type StringToSign struct {
	// Algorithm is the signing algorithm (AWS4-HMAC-SHA256)
	Algorithm string

	// RequestDateTime is the ISO8601 timestamp
	RequestDateTime string

	// CredentialScope is the credential scope string
	CredentialScope string

	// HashedCanonicalRequest is the SHA256 hash of the canonical request
	HashedCanonicalRequest string
}

// String returns the string to sign in the AWS SigV4 format:
// Algorithm + "\n" +
// RequestDateTime + "\n" +
// CredentialScope + "\n" +
// HashedCanonicalRequest
func (sts *StringToSign) String() string {
	return fmt.Sprintf("%s\n%s\n%s\n%s",
		sts.Algorithm,
		sts.RequestDateTime,
		sts.CredentialScope,
		sts.HashedCanonicalRequest,
	)
}

// CanonicalRequestOptions provides options for building canonical requests
type CanonicalRequestOptions struct {
	// DisableURIPathEscaping disables URI path encoding (for S3)
	DisableURIPathEscaping bool

	// AdditionalSignedHeaders specifies additional headers to include in the signature
	AdditionalSignedHeaders []string

	// UnsignedPayload indicates the payload should not be signed
	UnsignedPayload bool
}

// BuildCanonicalRequest builds a canonical request from an HTTP request
func BuildCanonicalRequest(req *http.Request, payloadHash string, opts *CanonicalRequestOptions) (*CanonicalRequest, error) {
	if opts == nil {
		opts = &CanonicalRequestOptions{}
	}

	// 1. HTTP Method
	method := req.Method

	// 2. Canonical URI
	canonicalURI := buildCanonicalURI(req.URL.Path, opts.DisableURIPathEscaping)

	// 3. Canonical Query String
	canonicalQuery := buildCanonicalQueryString(req.URL.Query())

	// 4. Determine which headers to sign
	signedHeaderNames := ExtractSignedHeaders(req.Header, opts.AdditionalSignedHeaders)

	// 5. Canonical Headers and Signed Headers list
	canonicalHeaders, signedHeaders := CanonicalizeHeaders(req.Header, signedHeaderNames)

	// 6. Payload hash
	if opts.UnsignedPayload {
		payloadHash = UnsignedPayload
	}

	return &CanonicalRequest{
		Method:               method,
		CanonicalURI:         canonicalURI,
		CanonicalQueryString: canonicalQuery,
		CanonicalHeaders:     canonicalHeaders,
		SignedHeaders:        signedHeaders,
		PayloadHash:          payloadHash,
	}, nil
}

// buildCanonicalURI builds the canonical URI path
func buildCanonicalURI(path string, disableEscaping bool) string {
	if path == "" {
		return "/"
	}

	// Normalize the path (remove redundant slashes)
	normalized := NormalizePath(path)

	// Encode according to RFC 3986 if not disabled
	if disableEscaping {
		return normalized
	}

	// Encode path (don't encode slashes for most services)
	return EncodeURI(normalized, false)
}

// buildCanonicalQueryString builds the canonical query string
func buildCanonicalQueryString(query url.Values) string {
	return EncodeQueryValues(query)
}

// BuildStringToSign builds the string to sign from a canonical request
func BuildStringToSign(canonicalReq *CanonicalRequest, service, region string, signTime time.Time) (*StringToSign, error) {
	// 1. Algorithm
	algorithm := Algorithm

	// 2. Request date/time in ISO8601 format
	requestDateTime := FormatSigningTime(signTime)

	// 3. Credential scope: date/region/service/aws4_request
	date := FormatSigningDate(signTime)
	credentialScope := BuildCredentialScope(date, region, service)

	// 4. Hash the canonical request
	hashedCanonicalRequest := ComputeStringHash(canonicalReq.String())

	return &StringToSign{
		Algorithm:              algorithm,
		RequestDateTime:        requestDateTime,
		CredentialScope:        credentialScope,
		HashedCanonicalRequest: hashedCanonicalRequest,
	}, nil
}

// BuildAuthorizationHeader builds the Authorization header value
// Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/SCOPE, SignedHeaders=HEADERS, Signature=SIGNATURE
func BuildAuthorizationHeader(accessKeyID, credentialScope, signedHeaders, signature string) string {
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		Algorithm,
		accessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)
}

// ParseAuthorizationHeader parses the Authorization header
// Returns credential (access key ID + scope), signed headers list, and signature
func ParseAuthorizationHeader(authHeader string) (credential, signedHeaders, signature string, err error) {
	// Check if it starts with the correct algorithm
	if !strings.HasPrefix(authHeader, Algorithm+" ") {
		return "", "", "", ErrInvalidAuthorizationHeader
	}

	// Remove the algorithm prefix
	remainder := strings.TrimPrefix(authHeader, Algorithm+" ")

	// Parse the key-value pairs
	parts := strings.Split(remainder, ", ")
	if len(parts) != 3 {
		return "", "", "", ErrInvalidAuthorizationHeader
	}

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return "", "", "", ErrInvalidAuthorizationHeader
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "Credential":
			credential = value
		case "SignedHeaders":
			signedHeaders = value
		case "Signature":
			signature = value
		default:
			return "", "", "", fmt.Errorf("%w: unknown key %q", ErrInvalidAuthorizationHeader, key)
		}
	}

	if credential == "" || signedHeaders == "" || signature == "" {
		return "", "", "", ErrInvalidAuthorizationHeader
	}

	return credential, signedHeaders, signature, nil
}

// ParseCredential parses the credential string from the Authorization header
// Format: ACCESS_KEY_ID/DATE/REGION/SERVICE/aws4_request
// Returns access key ID and credential scope
func ParseCredential(credential string) (accessKeyID, scope string, err error) {
	// Find the first '/' to separate access key ID from scope
	idx := strings.IndexByte(credential, '/')
	if idx == -1 {
		return "", "", fmt.Errorf("invalid credential format: no scope separator")
	}

	accessKeyID = credential[:idx]
	scope = credential[idx+1:]

	if accessKeyID == "" || scope == "" {
		return "", "", fmt.Errorf("invalid credential format: empty access key ID or scope")
	}

	return accessKeyID, scope, nil
}
