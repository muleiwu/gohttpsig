package gohttpsig

import "time"

// SignerOptions contains configuration options for the Signer
type SignerOptions struct {
	// UnsignedPayload indicates that the payload should not be signed
	// The payload hash will be set to "UNSIGNED-PAYLOAD"
	UnsignedPayload bool

	// DisableURIPathEscaping disables URI path encoding
	// This is typically used for S3-compatible services
	DisableURIPathEscaping bool

	// AdditionalSignedHeaders specifies additional headers to include in the signature
	// beyond the default set (host, x-amz-*, content-type)
	AdditionalSignedHeaders []string

	// DisableImplicitContentSHA256 disables automatically adding the X-Amz-Content-Sha256 header
	DisableImplicitContentSHA256 bool

	// OverrideSigningTime allows overriding the signing time (primarily for testing)
	OverrideSigningTime *time.Time
}

// SignerOption is a functional option for configuring the Signer
type SignerOption func(*SignerOptions)

// WithUnsignedPayload configures the signer to not sign the payload
// The X-Amz-Content-Sha256 header will be set to "UNSIGNED-PAYLOAD"
func WithUnsignedPayload() SignerOption {
	return func(opts *SignerOptions) {
		opts.UnsignedPayload = true
	}
}

// WithDisableURIPathEscaping disables URI path encoding
// This is typically used for S3-compatible services
func WithDisableURIPathEscaping() SignerOption {
	return func(opts *SignerOptions) {
		opts.DisableURIPathEscaping = true
	}
}

// WithAdditionalSignedHeaders adds additional headers to be included in the signature
func WithAdditionalSignedHeaders(headers ...string) SignerOption {
	return func(opts *SignerOptions) {
		opts.AdditionalSignedHeaders = append(opts.AdditionalSignedHeaders, headers...)
	}
}

// WithDisableImplicitContentSHA256 disables automatically adding the X-Amz-Content-Sha256 header
func WithDisableImplicitContentSHA256() SignerOption {
	return func(opts *SignerOptions) {
		opts.DisableImplicitContentSHA256 = true
	}
}

// WithSigningTime sets a specific signing time (primarily for testing)
func WithSigningTime(t time.Time) SignerOption {
	return func(opts *SignerOptions) {
		opts.OverrideSigningTime = &t
	}
}

// VerifierOptions contains configuration options for the Verifier
type VerifierOptions struct {
	// MaxTimestampDrift is the maximum allowed time difference between
	// the request timestamp and the current time
	MaxTimestampDrift time.Duration

	// DisableURIPathEscaping disables URI path encoding verification
	DisableURIPathEscaping bool

	// RequireSecurityToken indicates whether the X-Amz-Security-Token header is required
	RequireSecurityToken bool

	// AllowUnsignedPayload allows requests with "UNSIGNED-PAYLOAD" in the X-Amz-Content-Sha256 header
	AllowUnsignedPayload bool

	// OverrideCurrentTime allows overriding the current time for timestamp validation (testing)
	OverrideCurrentTime *time.Time
}

// VerifierOption is a functional option for configuring the Verifier
type VerifierOption func(*VerifierOptions)

// WithMaxTimestampDrift sets the maximum allowed time drift for request timestamps
// Default is 5 minutes if not specified
func WithMaxTimestampDrift(duration time.Duration) VerifierOption {
	return func(opts *VerifierOptions) {
		opts.MaxTimestampDrift = duration
	}
}

// WithVerifierDisableURIPathEscaping disables URI path encoding verification
func WithVerifierDisableURIPathEscaping() VerifierOption {
	return func(opts *VerifierOptions) {
		opts.DisableURIPathEscaping = true
	}
}

// WithRequireSecurityToken requires the X-Amz-Security-Token header to be present
func WithRequireSecurityToken() VerifierOption {
	return func(opts *VerifierOptions) {
		opts.RequireSecurityToken = true
	}
}

// WithAllowUnsignedPayload allows requests with unsigned payloads
func WithAllowUnsignedPayload() VerifierOption {
	return func(opts *VerifierOptions) {
		opts.AllowUnsignedPayload = true
	}
}

// WithVerifierCurrentTime sets the current time for timestamp validation (testing)
func WithVerifierCurrentTime(t time.Time) VerifierOption {
	return func(opts *VerifierOptions) {
		opts.OverrideCurrentTime = &t
	}
}

// applySignerOptions applies functional options to SignerOptions
func applySignerOptions(opts ...SignerOption) *SignerOptions {
	options := &SignerOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return options
}

// applyVerifierOptions applies functional options to VerifierOptions
func applyVerifierOptions(opts ...VerifierOption) *VerifierOptions {
	options := &VerifierOptions{
		// Default to 5 minute timestamp drift
		MaxTimestampDrift: 5 * time.Minute,
	}
	for _, opt := range opts {
		opt(options)
	}
	return options
}
