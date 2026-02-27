package gohttpsig

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Verifier verifies HTTP request signatures using AWS Signature Version 4
type Verifier struct {
	credentialStore CredentialStore
	options         *VerifierOptions
}

// NewVerifier creates a new Verifier with the given credential store and options
func NewVerifier(store CredentialStore, opts ...VerifierOption) *Verifier {
	return &Verifier{
		credentialStore: store,
		options:         applyVerifierOptions(opts...),
	}
}

// VerificationResult represents the result of signature verification
type VerificationResult struct {
	// Valid indicates whether the signature is valid
	Valid bool

	// AccessKeyID is the access key ID extracted from the request
	AccessKeyID string

	// SignedHeaders is the list of headers that were signed
	SignedHeaders []string

	// RequestTime is the timestamp from the request
	RequestTime time.Time

	// Service is the service name from the credential scope
	Service string

	// Region is the region from the credential scope
	Region string

	// Error contains any error that occurred during verification
	Error error
}

// Verify verifies the signature of an HTTP request
func (v *Verifier) Verify(ctx context.Context, req *http.Request) (*VerificationResult, error) {
	result := &VerificationResult{}

	// 1. Check for Authorization header
	authHeader := req.Header.Get(HeaderAuthorization)
	if authHeader == "" {
		result.Error = ErrMissingAuthorizationHeader
		return result, result.Error
	}

	// 2. Parse Authorization header
	credential, signedHeadersList, providedSignature, err := ParseAuthorizationHeader(authHeader)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "invalid authorization header",
			Err:    err,
		}
		return result, result.Error
	}

	// 3. Parse credential to extract access key ID and scope
	accessKeyID, scope, err := ParseCredential(credential)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "invalid credential format",
			Err:    err,
		}
		return result, result.Error
	}
	result.AccessKeyID = accessKeyID

	// 4. Parse credential scope to extract date, region, service
	date, region, service, err := ParseCredentialScope(scope)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "invalid credential scope",
			Err:    err,
		}
		return result, result.Error
	}
	result.Region = region
	result.Service = service

	// 5. Extract and validate timestamp
	timestamp := req.Header.Get(HeaderXAmzDate)
	if timestamp == "" {
		result.Error = &VerificationError{
			Reason: "missing X-Amz-Date header",
			Err:    ErrMissingRequiredHeader,
		}
		return result, result.Error
	}

	requestTime, err := ParseSigningTime(timestamp)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "invalid timestamp format",
			Err:    err,
		}
		return result, result.Error
	}
	result.RequestTime = requestTime

	// 6. Validate timestamp is within acceptable drift
	if err := v.validateTimestamp(requestTime); err != nil {
		result.Error = &VerificationError{
			Reason: "timestamp out of range",
			Err:    err,
		}
		return result, result.Error
	}

	// 7. Validate that the date in the credential scope matches the request date
	requestDate := FormatSigningDate(requestTime)
	if date != requestDate {
		result.Error = &VerificationError{
			Reason: fmt.Sprintf("credential scope date %s does not match request date %s", date, requestDate),
			Err:    ErrInvalidAuthorizationHeader,
		}
		return result, result.Error
	}

	// 8. Check for required security token if configured
	if v.options.RequireSecurityToken {
		if req.Header.Get(HeaderXAmzSecurityToken) == "" {
			result.Error = &VerificationError{
				Reason: "missing required X-Amz-Security-Token header",
				Err:    ErrMissingRequiredHeader,
			}
			return result, result.Error
		}
	}

	// 9. Retrieve credentials from store
	creds, err := v.credentialStore.GetCredentials(ctx, accessKeyID)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "credential lookup failed",
			Err:    err,
		}
		return result, result.Error
	}

	// 10. Parse signed headers list
	signedHeaders := strings.Split(signedHeadersList, ";")
	result.SignedHeaders = signedHeaders

	// 11. Get payload hash
	payloadHash := req.Header.Get(HeaderXAmzContentSHA256)
	if payloadHash == "" {
		// Compute payload hash from body if not provided
		computedHash, err := v.computePayloadHash(req)
		if err != nil {
			result.Error = &VerificationError{
				Reason: "failed to compute payload hash",
				Err:    err,
			}
			return result, result.Error
		}
		payloadHash = computedHash
	} else if payloadHash == UnsignedPayload {
		// Check if unsigned payload is allowed
		if !v.options.AllowUnsignedPayload {
			result.Error = &VerificationError{
				Reason: "unsigned payload not allowed",
				Err:    ErrInvalidSignature,
			}
			return result, result.Error
		}
	}

	// 12. Build canonical request
	canonicalOpts := &CanonicalRequestOptions{
		DisableURIPathEscaping:  v.options.DisableURIPathEscaping,
		AdditionalSignedHeaders: signedHeaders,
	}

	canonicalReq, err := v.buildCanonicalRequestForVerification(req, payloadHash, signedHeaders, canonicalOpts)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "failed to build canonical request",
			Err:    err,
		}
		return result, result.Error
	}

	// 13. Build string to sign
	stringToSign, err := BuildStringToSign(canonicalReq, service, region, requestTime)
	if err != nil {
		result.Error = &VerificationError{
			Reason: "failed to build string to sign",
			Err:    err,
		}
		return result, result.Error
	}

	// 14. Derive signing key
	signingKey := DeriveSigningKey(creds.SecretAccessKey, date, region, service)

	// 15. Compute expected signature
	expectedSignature := ComputeSignature(signingKey, stringToSign.String())

	// 16. Compare signatures using constant-time comparison
	if !VerifySignature(expectedSignature, providedSignature) {
		result.Error = &VerificationError{
			Reason: "signature mismatch",
			Err:    ErrInvalidSignature,
		}
		return result, result.Error
	}

	// Signature is valid
	result.Valid = true
	return result, nil
}

// validateTimestamp checks if the request timestamp is within acceptable drift
func (v *Verifier) validateTimestamp(requestTime time.Time) error {
	currentTime := time.Now().UTC()
	if v.options.OverrideCurrentTime != nil {
		currentTime = *v.options.OverrideCurrentTime
	}

	drift := currentTime.Sub(requestTime)
	if drift < 0 {
		drift = -drift
	}

	if drift > v.options.MaxTimestampDrift {
		return ErrTimestampOutOfRange
	}

	return nil
}

// computePayloadHash computes the hash of the request payload
func (v *Verifier) computePayloadHash(req *http.Request) (string, error) {
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

// buildCanonicalRequestForVerification builds a canonical request for verification
// This uses the exact signed headers from the Authorization header
func (v *Verifier) buildCanonicalRequestForVerification(req *http.Request, payloadHash string, signedHeaders []string, opts *CanonicalRequestOptions) (*CanonicalRequest, error) {
	// 1. HTTP Method
	method := req.Method

	// 2. Canonical URI
	canonicalURI := buildCanonicalURI(req.URL.Path, opts.DisableURIPathEscaping)

	// 3. Canonical Query String
	canonicalQuery := buildCanonicalQueryString(req.URL.Query())

	// 4. Canonical Headers - use exactly the signed headers from the request
	canonicalHeaders, signedHeadersList := CanonicalizeHeaders(req.Header, signedHeaders)

	return &CanonicalRequest{
		Method:               method,
		CanonicalURI:         canonicalURI,
		CanonicalQueryString: canonicalQuery,
		CanonicalHeaders:     canonicalHeaders,
		SignedHeaders:        signedHeadersList,
		PayloadHash:          payloadHash,
	}, nil
}
