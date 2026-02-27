package gohttpsig

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSignerSign(t *testing.T) {
	// Create test credentials
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)

	// Create test request
	req, err := http.NewRequest("GET", "https://example.com/path/to/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify Authorization header was added
	authHeader := signed.Request.Header.Get(HeaderAuthorization)
	if authHeader == "" {
		t.Error("Authorization header not added")
	}

	// Verify it starts with the correct algorithm
	if !strings.HasPrefix(authHeader, Algorithm) {
		t.Errorf("Authorization header should start with %q, got %q", Algorithm, authHeader)
	}

	// Verify X-Amz-Date header was added
	dateHeader := signed.Request.Header.Get(HeaderXAmzDate)
	if dateHeader == "" {
		t.Error("X-Amz-Date header not added")
	}

	// Verify X-Amz-Content-Sha256 header was added
	contentSha := signed.Request.Header.Get(HeaderXAmzContentSHA256)
	if contentSha == "" {
		t.Error("X-Amz-Content-Sha256 header not added")
	}

	// Verify signature is not empty
	if signed.Signature == "" {
		t.Error("Signature is empty")
	}

	// Verify signed headers is not empty
	if signed.SignedHeaders == "" {
		t.Error("SignedHeaders is empty")
	}
}

func TestSignerSignWithBody(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)

	// Create test request with body
	body := strings.NewReader(`{"key": "value"}`)
	req, err := http.NewRequest("POST", "https://example.com/api", body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify Authorization header was added
	authHeader := signed.Request.Header.Get(HeaderAuthorization)
	if authHeader == "" {
		t.Error("Authorization header not added")
	}

	// Verify content hash is not empty or unsigned
	contentSha := signed.Request.Header.Get(HeaderXAmzContentSHA256)
	if contentSha == "" || contentSha == UnsignedPayload {
		t.Error("Content hash should be computed for body")
	}

	// Verify body can still be read
	if signed.Request.Body == nil {
		t.Error("Request body should not be nil after signing")
	}
}

func TestSignerSignWithUnsignedPayload(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider, WithUnsignedPayload())

	// Create test request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify content hash is UNSIGNED-PAYLOAD
	contentSha := signed.Request.Header.Get(HeaderXAmzContentSHA256)
	if contentSha != UnsignedPayload {
		t.Errorf("Content hash should be %q, got %q", UnsignedPayload, contentSha)
	}
}

func TestSignerSignWithSessionToken(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token-12345",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)

	// Create test request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify X-Amz-Security-Token header was added
	token := signed.Request.Header.Get(HeaderXAmzSecurityToken)
	if token != creds.SessionToken {
		t.Errorf("X-Amz-Security-Token = %q, want %q", token, creds.SessionToken)
	}
}

func TestSignerPresignRequest(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)

	// Create test request
	req, err := http.NewRequest("GET", "https://example.com/path/to/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Presign the request
	expiresIn := 15 * time.Minute
	presignedURL, err := signer.PresignRequest(context.Background(), req, "myservice", "us-east-1", expiresIn)
	if err != nil {
		t.Fatalf("PresignRequest() error = %v", err)
	}

	// Verify query parameters were added
	query := presignedURL.Query()

	if query.Get("X-Amz-Algorithm") != Algorithm {
		t.Errorf("X-Amz-Algorithm = %q, want %q", query.Get("X-Amz-Algorithm"), Algorithm)
	}

	if query.Get("X-Amz-Credential") == "" {
		t.Error("X-Amz-Credential not added")
	}

	if query.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date not added")
	}

	if query.Get("X-Amz-Expires") != "900" { // 15 minutes = 900 seconds
		t.Errorf("X-Amz-Expires = %q, want %q", query.Get("X-Amz-Expires"), "900")
	}

	if query.Get("X-Amz-SignedHeaders") == "" {
		t.Error("X-Amz-SignedHeaders not added")
	}

	if query.Get("X-Amz-Signature") == "" {
		t.Error("X-Amz-Signature not added")
	}
}

func TestSignerSignConsistency(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	fixedTime := time.Date(2026, 2, 27, 12, 0, 0, 0, time.UTC)
	signer := NewSigner(provider, WithSigningTime(fixedTime))

	// Create test request
	req1, _ := http.NewRequest("GET", "https://example.com/path", nil)
	req2, _ := http.NewRequest("GET", "https://example.com/path", nil)

	// Sign both requests
	signed1, err := signer.Sign(context.Background(), req1, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signed2, err := signer.Sign(context.Background(), req2, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Signatures should be identical
	if signed1.Signature != signed2.Signature {
		t.Error("Same request signed twice should produce identical signatures")
	}
}

func TestSignerSignWithQueryParameters(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)

	// Create request with query parameters
	baseURL := "https://example.com/path"
	params := url.Values{}
	params.Set("key1", "value1")
	params.Set("key2", "value with spaces")

	reqURL := baseURL + "?" + params.Encode()
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify Authorization header was added
	authHeader := signed.Request.Header.Get(HeaderAuthorization)
	if authHeader == "" {
		t.Error("Authorization header not added")
	}
}

func BenchmarkSignerSign(b *testing.B) {
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)

	req, _ := http.NewRequest("GET", "https://example.com/path/to/resource", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(context.Background(), req, "myservice", "us-east-1")
	}
}
