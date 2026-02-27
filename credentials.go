package gohttpsig

import (
	"context"
	"fmt"
)

// Credentials represents AWS-style credentials used for signing requests
type Credentials struct {
	// AccessKeyID is the access key identifier
	AccessKeyID string

	// SecretAccessKey is the secret key used for signing
	SecretAccessKey string

	// SessionToken is an optional session token for temporary credentials
	SessionToken string
}

// Validate checks if the credentials are valid
func (c *Credentials) Validate() error {
	if c == nil {
		return ErrInvalidCredentials
	}

	if c.AccessKeyID == "" {
		return &ValidationError{
			Field: "AccessKeyID",
			Err:   fmt.Errorf("access key ID cannot be empty"),
		}
	}

	if c.SecretAccessKey == "" {
		return &ValidationError{
			Field: "SecretAccessKey",
			Err:   fmt.Errorf("secret access key cannot be empty"),
		}
	}

	return nil
}

// CredentialsProvider is an interface for retrieving credentials
// This allows for different credential sources (static, environment, files, etc.)
type CredentialsProvider interface {
	// Retrieve retrieves credentials from the provider
	Retrieve(ctx context.Context) (*Credentials, error)
}

// StaticCredentialsProvider provides credentials from a static source
type StaticCredentialsProvider struct {
	creds *Credentials
}

// NewStaticCredentialsProvider creates a new static credentials provider
func NewStaticCredentialsProvider(creds *Credentials) *StaticCredentialsProvider {
	return &StaticCredentialsProvider{
		creds: creds,
	}
}

// Retrieve returns the static credentials
func (p *StaticCredentialsProvider) Retrieve(ctx context.Context) (*Credentials, error) {
	if p.creds == nil {
		return nil, ErrInvalidCredentials
	}

	if err := p.creds.Validate(); err != nil {
		return nil, err
	}

	return p.creds, nil
}

// CredentialStore is an interface for looking up credentials by access key ID
// This is used on the server side for signature verification
type CredentialStore interface {
	// GetCredentials retrieves credentials for the given access key ID
	GetCredentials(ctx context.Context, accessKeyID string) (*Credentials, error)
}

// InMemoryCredentialStore is a simple in-memory implementation of CredentialStore
// This is primarily for testing and simple use cases
type InMemoryCredentialStore struct {
	credentials map[string]*Credentials
}

// NewInMemoryCredentialStore creates a new in-memory credential store
func NewInMemoryCredentialStore() *InMemoryCredentialStore {
	return &InMemoryCredentialStore{
		credentials: make(map[string]*Credentials),
	}
}

// AddCredentials adds credentials to the store
func (s *InMemoryCredentialStore) AddCredentials(creds *Credentials) error {
	if err := creds.Validate(); err != nil {
		return err
	}

	s.credentials[creds.AccessKeyID] = creds
	return nil
}

// GetCredentials retrieves credentials for the given access key ID
func (s *InMemoryCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*Credentials, error) {
	creds, ok := s.credentials[accessKeyID]
	if !ok {
		return nil, ErrCredentialNotFound
	}

	return creds, nil
}

// RemoveCredentials removes credentials from the store
func (s *InMemoryCredentialStore) RemoveCredentials(accessKeyID string) {
	delete(s.credentials, accessKeyID)
}
