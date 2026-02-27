package gohttpsig

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Signer signs HTTP requests using AWS Signature Version 4
type Signer struct {
	credentials CredentialsProvider
	options     *SignerOptions
}

// NewSigner creates a new Signer with the given credentials provider and options
func NewSigner(creds CredentialsProvider, opts ...SignerOption) *Signer {
	return &Signer{
		credentials: creds,
		options:     applySignerOptions(opts...),
	}
}

// SignedRequest represents a signed HTTP request
type SignedRequest struct {
	// Request is the signed HTTP request
	Request *http.Request

	// Signature is the computed signature
	Signature string

	// SignedHeaders is the list of headers included in the signature
	SignedHeaders string

	// CredentialScope is the credential scope string
	CredentialScope string

	// SigningTime is the time used for signing
	SigningTime time.Time
}

// Sign signs an HTTP request and returns a SignedRequest
// The original request is cloned and the Authorization header is added
func (s *Signer) Sign(ctx context.Context, req *http.Request, service, region string) (*SignedRequest, error) {
	// Retrieve credentials
	creds, err := s.credentials.Retrieve(ctx)
	if err != nil {
		return nil, &SigningError{
			Operation: "retrieve credentials",
			Err:       err,
		}
	}

	// Clone the request to avoid modifying the original
	signedReq := cloneRequest(req)

	// Determine signing time
	signTime := time.Now().UTC()
	if s.options.OverrideSigningTime != nil {
		signTime = *s.options.OverrideSigningTime
	}

	// Add required headers
	if err := s.addRequiredHeaders(signedReq, creds, signTime); err != nil {
		return nil, &SigningError{
			Operation: "add required headers",
			Err:       err,
		}
	}

	// Compute payload hash
	payloadHash, err := s.computePayloadHash(signedReq)
	if err != nil {
		return nil, &SigningError{
			Operation: "compute payload hash",
			Err:       err,
		}
	}

	// Add X-Amz-Content-Sha256 header if not disabled
	if !s.options.DisableImplicitContentSHA256 {
		signedReq.Header.Set(HeaderXAmzContentSHA256, payloadHash)
	}

	// Build canonical request
	canonicalOpts := &CanonicalRequestOptions{
		DisableURIPathEscaping:  s.options.DisableURIPathEscaping,
		AdditionalSignedHeaders: s.options.AdditionalSignedHeaders,
		UnsignedPayload:         s.options.UnsignedPayload,
	}

	canonicalReq, err := BuildCanonicalRequest(signedReq, payloadHash, canonicalOpts)
	if err != nil {
		return nil, &SigningError{
			Operation: "build canonical request",
			Err:       err,
		}
	}

	// Build string to sign
	stringToSign, err := BuildStringToSign(canonicalReq, service, region, signTime)
	if err != nil {
		return nil, &SigningError{
			Operation: "build string to sign",
			Err:       err,
		}
	}

	// Derive signing key
	date := FormatSigningDate(signTime)
	signingKey := DeriveSigningKey(creds.SecretAccessKey, date, region, service)

	// Compute signature
	signature := ComputeSignature(signingKey, stringToSign.String())

	// Build Authorization header
	authHeader := BuildAuthorizationHeader(
		creds.AccessKeyID,
		stringToSign.CredentialScope,
		canonicalReq.SignedHeaders,
		signature,
	)

	// Add Authorization header
	signedReq.Header.Set(HeaderAuthorization, authHeader)

	return &SignedRequest{
		Request:         signedReq,
		Signature:       signature,
		SignedHeaders:   canonicalReq.SignedHeaders,
		CredentialScope: stringToSign.CredentialScope,
		SigningTime:     signTime,
	}, nil
}

// PresignRequest creates a presigned URL for an HTTP request
// The presigned URL can be used by clients without credentials
func (s *Signer) PresignRequest(ctx context.Context, req *http.Request, service, region string, expiresIn time.Duration) (*url.URL, error) {
	// Retrieve credentials
	creds, err := s.credentials.Retrieve(ctx)
	if err != nil {
		return nil, &SigningError{
			Operation: "retrieve credentials",
			Err:       err,
		}
	}

	// Determine signing time
	signTime := time.Now().UTC()
	if s.options.OverrideSigningTime != nil {
		signTime = *s.options.OverrideSigningTime
	}

	// Clone the URL
	presignedURL := cloneURL(req.URL)

	// Build credential scope
	date := FormatSigningDate(signTime)
	credentialScope := BuildCredentialScope(date, region, service)
	credential := creds.AccessKeyID + "/" + credentialScope

	// Add query parameters for presigned request
	query := presignedURL.Query()
	query.Set("X-Amz-Algorithm", Algorithm)
	query.Set("X-Amz-Credential", credential)
	query.Set("X-Amz-Date", FormatSigningTime(signTime))
	query.Set("X-Amz-Expires", strconv.FormatInt(int64(expiresIn.Seconds()), 10))

	// Add security token if present
	if creds.SessionToken != "" {
		query.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Build signed headers list (for presigned URLs, typically just "host")
	signedHeaders := "host"
	query.Set("X-Amz-SignedHeaders", signedHeaders)

	presignedURL.RawQuery = query.Encode()

	// Create a temporary request for building canonical request
	tempReq := &http.Request{
		Method: req.Method,
		URL:    presignedURL,
		Header: make(http.Header),
	}
	tempReq.Header.Set(HeaderHost, req.Host)
	if req.Host == "" && req.URL != nil {
		tempReq.Header.Set(HeaderHost, req.URL.Host)
	}

	// Build canonical request
	canonicalOpts := &CanonicalRequestOptions{
		DisableURIPathEscaping:  s.options.DisableURIPathEscaping,
		AdditionalSignedHeaders: []string{HeaderHost},
		UnsignedPayload:         true, // Presigned URLs always use unsigned payload
	}

	canonicalReq, err := BuildCanonicalRequest(tempReq, UnsignedPayload, canonicalOpts)
	if err != nil {
		return nil, &SigningError{
			Operation: "build canonical request for presigning",
			Err:       err,
		}
	}

	// Build string to sign
	stringToSign, err := BuildStringToSign(canonicalReq, service, region, signTime)
	if err != nil {
		return nil, &SigningError{
			Operation: "build string to sign for presigning",
			Err:       err,
		}
	}

	// Derive signing key and compute signature
	signingKey := DeriveSigningKey(creds.SecretAccessKey, date, region, service)
	signature := ComputeSignature(signingKey, stringToSign.String())

	// Add signature to query parameters
	query = presignedURL.Query()
	query.Set("X-Amz-Signature", signature)
	presignedURL.RawQuery = query.Encode()

	return presignedURL, nil
}

// addRequiredHeaders adds required headers to the request
func (s *Signer) addRequiredHeaders(req *http.Request, creds *Credentials, signTime time.Time) error {
	// Add Host header if not present
	if req.Header.Get(HeaderHost) == "" {
		host := req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		if host != "" {
			req.Header.Set(HeaderHost, host)
		}
	}

	// Add X-Amz-Date header
	req.Header.Set(HeaderXAmzDate, FormatSigningTime(signTime))

	// Add X-Amz-Security-Token if session token is present
	if creds.SessionToken != "" {
		req.Header.Set(HeaderXAmzSecurityToken, creds.SessionToken)
	}

	return nil
}

// computePayloadHash computes the hash of the request payload
func (s *Signer) computePayloadHash(req *http.Request) (string, error) {
	if s.options.UnsignedPayload {
		return UnsignedPayload, nil
	}

	if req.Body == nil {
		return ComputePayloadHashFromBytes(nil), nil
	}

	// Read the body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore the body so it can be read again
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Compute hash
	return ComputePayloadHashFromBytes(bodyBytes), nil
}

// cloneRequest creates a deep copy of an HTTP request
func cloneRequest(req *http.Request) *http.Request {
	clone := new(http.Request)
	*clone = *req

	// Clone URL
	if req.URL != nil {
		cloneURL := new(url.URL)
		*cloneURL = *req.URL
		clone.URL = cloneURL
	}

	// Clone headers
	clone.Header = make(http.Header)
	for k, v := range req.Header {
		clone.Header[k] = append([]string(nil), v...)
	}

	return clone
}

// cloneURL creates a deep copy of a URL
func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}

	clone := new(url.URL)
	*clone = *u

	if u.User != nil {
		clone.User = &url.Userinfo{}
		*clone.User = *u.User
	}

	return clone
}
