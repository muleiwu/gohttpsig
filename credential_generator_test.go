package gohttpsig

import (
	"strings"
	"testing"
)

func TestGenerateAccessKeyID(t *testing.T) {
	// Test with different prefixes
	prefixes := []CredentialPrefix{
		PrefixPermanent,
		PrefixTemporary,
		PrefixService,
	}

	for _, prefix := range prefixes {
		t.Run(string(prefix), func(t *testing.T) {
			accessKeyID, err := GenerateAccessKeyID(prefix)
			if err != nil {
				t.Fatalf("GenerateAccessKeyID() error = %v", err)
			}

			// Check length
			if len(accessKeyID) != AccessKeyIDLength {
				t.Errorf("AccessKeyID length = %d, want %d", len(accessKeyID), AccessKeyIDLength)
			}

			// Check prefix
			if !strings.HasPrefix(accessKeyID, string(prefix)) {
				t.Errorf("AccessKeyID prefix = %s, want %s", accessKeyID[:4], prefix)
			}

			// Validate format
			if err := ValidateAccessKeyID(accessKeyID); err != nil {
				t.Errorf("Generated AccessKeyID failed validation: %v", err)
			}
		})
	}
}

func TestGenerateAccessKeyIDUniqueness(t *testing.T) {
	// Generate multiple IDs and ensure they're unique
	ids := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		id, err := GenerateAccessKeyID(PrefixPermanent)
		if err != nil {
			t.Fatalf("GenerateAccessKeyID() error = %v", err)
		}

		if ids[id] {
			t.Errorf("Duplicate AccessKeyID generated: %s", id)
		}
		ids[id] = true
	}

	if len(ids) != iterations {
		t.Errorf("Generated %d unique IDs, expected %d", len(ids), iterations)
	}
}

func TestGenerateSecretAccessKey(t *testing.T) {
	secret, err := GenerateSecretAccessKey()
	if err != nil {
		t.Fatalf("GenerateSecretAccessKey() error = %v", err)
	}

	// Check length
	if len(secret) != SecretAccessKeyLength {
		t.Errorf("SecretAccessKey length = %d, want %d", len(secret), SecretAccessKeyLength)
	}

	// Validate strength
	if err := ValidateSecretAccessKey(secret); err != nil {
		t.Errorf("Generated SecretAccessKey failed validation: %v", err)
	}
}

func TestGenerateSecretAccessKeyUniqueness(t *testing.T) {
	// Generate multiple keys and ensure they're unique
	keys := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		key, err := GenerateSecretAccessKey()
		if err != nil {
			t.Fatalf("GenerateSecretAccessKey() error = %v", err)
		}

		if keys[key] {
			t.Errorf("Duplicate SecretAccessKey generated: %s", key)
		}
		keys[key] = true
	}

	if len(keys) != iterations {
		t.Errorf("Generated %d unique keys, expected %d", len(keys), iterations)
	}
}

func TestGenerateCredentials(t *testing.T) {
	creds, err := GenerateCredentials()
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	// Validate
	if err := creds.Validate(); err != nil {
		t.Errorf("Generated credentials failed validation: %v", err)
	}

	// Check AccessKeyID
	if err := ValidateAccessKeyID(creds.AccessKeyID); err != nil {
		t.Errorf("AccessKeyID validation failed: %v", err)
	}

	// Check SecretAccessKey
	if err := ValidateSecretAccessKey(creds.SecretAccessKey); err != nil {
		t.Errorf("SecretAccessKey validation failed: %v", err)
	}
}

func TestGenerateSessionToken(t *testing.T) {
	token, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken() error = %v", err)
	}

	// Check length (should be substantial)
	if len(token) < 64 {
		t.Errorf("SessionToken length = %d, want at least 64", len(token))
	}

	// Check uniqueness
	token2, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken() error = %v", err)
	}

	if token == token2 {
		t.Error("Session tokens should be unique")
	}
}

func TestValidateAccessKeyID(t *testing.T) {
	tests := []struct {
		name        string
		accessKeyID string
		wantErr     bool
	}{
		{
			name:        "valid permanent",
			accessKeyID: "AKIAIOSFODNN7EXAMPLE",
			wantErr:     false,
		},
		{
			name:        "valid temporary",
			accessKeyID: "ASIAIOSFODNN7EXAMPLE",
			wantErr:     false,
		},
		{
			name:        "too short",
			accessKeyID: "AKIASHORT",
			wantErr:     true,
		},
		{
			name:        "too long",
			accessKeyID: "AKIAIOSFODNN7EXAMPLETOOLONG",
			wantErr:     true,
		},
		{
			name:        "invalid prefix",
			accessKeyID: "XXIAIOSFODNN7EXAMPLE",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAccessKeyID(tt.accessKeyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAccessKeyID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecretAccessKey(t *testing.T) {
	tests := []struct {
		name      string
		secretKey string
		wantErr   bool
	}{
		{
			name:      "valid key",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantErr:   false,
		},
		{
			name:      "too short",
			secretKey: "short",
			wantErr:   true,
		},
		{
			name:      "no character diversity",
			secretKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantErr:   true,
		},
		{
			name:      "only lowercase",
			secretKey: "abcdefghijklmnopqrstuvwxyzabcdefghijklmn",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretAccessKey(tt.secretKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSecretAccessKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateCredentialStrength(t *testing.T) {
	tests := []struct {
		name       string
		creds      *Credentials
		wantStrong bool
		minScore   int
	}{
		{
			name: "strong credentials",
			creds: &Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantStrong: true,
			minScore:   90,
		},
		{
			name: "weak secret key",
			creds: &Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "short",
			},
			wantStrong: false,
			minScore:   0,
		},
		{
			name: "invalid access key",
			creds: &Credentials{
				AccessKeyID:     "INVALID",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantStrong: false,
			minScore:   70, // Will be 80 (100 - 20 for invalid access key)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength := EvaluateCredentialStrength(tt.creds)

			if strength.IsStrong != tt.wantStrong {
				t.Errorf("IsStrong = %v, want %v (Score: %d, Issues: %v)",
					strength.IsStrong, tt.wantStrong, strength.Score, strength.Issues)
			}

			if strength.Score < tt.minScore {
				t.Errorf("Score = %d, want at least %d (Issues: %v)",
					strength.Score, tt.minScore, strength.Issues)
			}
		})
	}
}

func BenchmarkGenerateAccessKeyID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateAccessKeyID(PrefixPermanent)
	}
}

func BenchmarkGenerateSecretAccessKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecretAccessKey()
	}
}

func BenchmarkGenerateCredentials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateCredentials()
	}
}
