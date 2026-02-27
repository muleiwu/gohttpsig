package gohttpsig

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestRoundTrip tests the full round-trip: sign with Signer, verify with Verifier
func TestRoundTrip(t *testing.T) {
	// Setup credentials
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Create credential store
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(creds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer and verifier
	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)
	verifier := NewVerifier(store)

	// Create and sign request
	req, err := http.NewRequest("GET", "https://example.com/path/to/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed request
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// Check verification result
	if !result.Valid {
		t.Errorf("Verification failed: %v", result.Error)
	}

	if result.AccessKeyID != creds.AccessKeyID {
		t.Errorf("AccessKeyID = %q, want %q", result.AccessKeyID, creds.AccessKeyID)
	}

	if result.Service != "myservice" {
		t.Errorf("Service = %q, want %q", result.Service, "myservice")
	}

	if result.Region != "us-east-1" {
		t.Errorf("Region = %q, want %q", result.Region, "us-east-1")
	}
}

// TestRoundTripWithBody tests signing and verification with request body
func TestRoundTripWithBody(t *testing.T) {
	// Setup credentials
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Create credential store
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(creds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer and verifier
	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)
	verifier := NewVerifier(store)

	// Create request with body
	body := strings.NewReader(`{"key": "value"}`)
	req, err := http.NewRequest("POST", "https://example.com/api/resource", body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed request
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// Check verification result
	if !result.Valid {
		t.Errorf("Verification failed: %v", result.Error)
	}
}

// TestRoundTripWithSessionToken tests signing and verification with session token
func TestRoundTripWithSessionToken(t *testing.T) {
	// Setup credentials with session token
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token-12345",
	}

	// Create credential store
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(creds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer and verifier
	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)
	verifier := NewVerifier(store)

	// Create and sign request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed request
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// Check verification result
	if !result.Valid {
		t.Errorf("Verification failed: %v", result.Error)
	}
}

// TestRoundTripWithUnsignedPayload tests signing and verification with unsigned payload
func TestRoundTripWithUnsignedPayload(t *testing.T) {
	// Setup credentials
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Create credential store
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(creds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer and verifier (with unsigned payload allowed)
	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider, WithUnsignedPayload())
	verifier := NewVerifier(store, WithAllowUnsignedPayload())

	// Create request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed request
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// Check verification result
	if !result.Valid {
		t.Errorf("Verification failed: %v", result.Error)
	}
}

// TestVerificationFailsWithWrongCredentials tests that verification fails with wrong credentials
func TestVerificationFailsWithWrongCredentials(t *testing.T) {
	// Setup signing credentials
	signingCreds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Setup verification credentials (different secret)
	verificationCreds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "WRONG-SECRET-KEY",
	}

	// Create credential store with wrong credentials
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(verificationCreds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer and verifier
	provider := NewStaticCredentialsProvider(signingCreds)
	signer := NewSigner(provider)
	verifier := NewVerifier(store)

	// Create and sign request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed request (should fail)
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err == nil {
		t.Error("Expected verification to fail with wrong credentials")
	}

	if result.Valid {
		t.Error("Verification should not be valid with wrong credentials")
	}
}

// TestVerificationFailsWithExpiredTimestamp tests that verification fails with expired timestamp
func TestVerificationFailsWithExpiredTimestamp(t *testing.T) {
	// Setup credentials
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Create credential store
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(creds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer with old timestamp
	provider := NewStaticCredentialsProvider(creds)
	oldTime := time.Now().UTC().Add(-10 * time.Minute) // 10 minutes ago
	signer := NewSigner(provider, WithSigningTime(oldTime))

	// Create verifier with short timestamp drift
	verifier := NewVerifier(store, WithMaxTimestampDrift(1*time.Minute))

	// Create and sign request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed request (should fail due to timestamp)
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err == nil {
		t.Error("Expected verification to fail with expired timestamp")
	}

	if result.Valid {
		t.Error("Verification should not be valid with expired timestamp")
	}
}

// TestVerificationFailsWithModifiedRequest tests that verification fails if request is modified
func TestVerificationFailsWithModifiedRequest(t *testing.T) {
	// Setup credentials
	creds := &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Create credential store
	store := NewInMemoryCredentialStore()
	if err := store.AddCredentials(creds); err != nil {
		t.Fatalf("Failed to add credentials: %v", err)
	}

	// Create signer and verifier
	provider := NewStaticCredentialsProvider(creds)
	signer := NewSigner(provider)
	verifier := NewVerifier(store)

	// Create and sign request
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Modify the request after signing (add a query parameter)
	signed.Request.URL.RawQuery = "modified=true"

	// Verify the signed request (should fail)
	result, err := verifier.Verify(context.Background(), signed.Request)
	if err == nil {
		t.Error("Expected verification to fail with modified request")
	}

	if result.Valid {
		t.Error("Verification should not be valid with modified request")
	}
}
