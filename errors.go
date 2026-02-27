package gohttpsig

import (
	"errors"
	"fmt"
)

// Sentinel errors
var (
	// ErrInvalidCredentials indicates that the credentials are invalid or missing required fields
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrMissingAuthorizationHeader indicates that the Authorization header is missing from the request
	ErrMissingAuthorizationHeader = errors.New("missing authorization header")

	// ErrInvalidAuthorizationHeader indicates that the Authorization header format is invalid
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header format")

	// ErrInvalidSignature indicates that the signature does not match the computed signature
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrTimestampOutOfRange indicates that the request timestamp is outside the acceptable range
	ErrTimestampOutOfRange = errors.New("timestamp out of acceptable range")

	// ErrMissingRequiredHeader indicates that a required header is missing from the request
	ErrMissingRequiredHeader = errors.New("missing required header")

	// ErrCredentialNotFound indicates that the credential was not found in the credential store
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrInvalidTimestamp indicates that the timestamp format is invalid
	ErrInvalidTimestamp = errors.New("invalid timestamp format")

	// ErrEmptyPayload indicates that the payload is empty when it should not be
	ErrEmptyPayload = errors.New("empty payload")
)

// SigningError represents an error that occurred during the signing process
type SigningError struct {
	Operation string
	Err       error
}

func (e *SigningError) Error() string {
	return fmt.Sprintf("signing error during %s: %v", e.Operation, e.Err)
}

func (e *SigningError) Unwrap() error {
	return e.Err
}

// VerificationError represents an error that occurred during signature verification
type VerificationError struct {
	Reason string
	Err    error
}

func (e *VerificationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("verification failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("verification failed: %s", e.Reason)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

// ValidationError represents a validation error
type ValidationError struct {
	Field string
	Err   error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field %s: %v", e.Field, e.Err)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}
