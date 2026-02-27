package gohttpsig

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDeriveSigningKey(t *testing.T) {
	// Test with AWS example values
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	service := "iam"

	key := DeriveSigningKey(secret, date, region, service)

	// The key should be 32 bytes (SHA256 output)
	if len(key) != 32 {
		t.Errorf("DeriveSigningKey returned key of length %d, want 32", len(key))
	}

	// Test consistency - same inputs should produce same output
	key2 := DeriveSigningKey(secret, date, region, service)
	if !bytes.Equal(key, key2) {
		t.Error("DeriveSigningKey is not deterministic")
	}

	// Different inputs should produce different keys
	key3 := DeriveSigningKey(secret, "20150831", region, service)
	if bytes.Equal(key, key3) {
		t.Error("Different dates produced the same signing key")
	}
}

func TestComputeSignature(t *testing.T) {
	signingKey := []byte("test-signing-key")
	stringToSign := "test-string-to-sign"

	signature := ComputeSignature(signingKey, stringToSign)

	// Signature should be a hex string
	if len(signature) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Errorf("ComputeSignature returned signature of length %d, want 64", len(signature))
	}

	// Should be lowercase hex
	if signature != strings.ToLower(signature) {
		t.Error("ComputeSignature should return lowercase hex")
	}

	// Test consistency
	signature2 := ComputeSignature(signingKey, stringToSign)
	if signature != signature2 {
		t.Error("ComputeSignature is not deterministic")
	}
}

func TestComputePayloadHashFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected string // SHA256 hash
	}{
		{
			name:     "empty payload",
			payload:  nil,
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "empty byte slice",
			payload:  []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "simple payload",
			payload:  []byte("test"),
			expected: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputePayloadHashFromBytes(tt.payload)
			if result != tt.expected {
				t.Errorf("ComputePayloadHashFromBytes() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestComputeStringHash(t *testing.T) {
	tests := []struct {
		data     string
		expected string
	}{
		{
			data:     "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			data:     "test",
			expected: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}

	for _, tt := range tests {
		result := ComputeStringHash(tt.data)
		if result != tt.expected {
			t.Errorf("ComputeStringHash(%q) = %q, want %q", tt.data, result, tt.expected)
		}
	}
}

func TestFormatSigningTime(t *testing.T) {
	testTime := time.Date(2026, 2, 27, 12, 30, 45, 0, time.UTC)
	expected := "20260227T123045Z"

	result := FormatSigningTime(testTime)
	if result != expected {
		t.Errorf("FormatSigningTime() = %q, want %q", result, expected)
	}
}

func TestFormatSigningDate(t *testing.T) {
	testTime := time.Date(2026, 2, 27, 12, 30, 45, 0, time.UTC)
	expected := "20260227"

	result := FormatSigningDate(testTime)
	if result != expected {
		t.Errorf("FormatSigningDate() = %q, want %q", result, expected)
	}
}

func TestParseSigningTime(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		wantTime  time.Time
		wantErr   bool
	}{
		{
			name:      "valid timestamp",
			timestamp: "20260227T123045Z",
			wantTime:  time.Date(2026, 2, 27, 12, 30, 45, 0, time.UTC),
			wantErr:   false,
		},
		{
			name:      "invalid format",
			timestamp: "2026-02-27T12:30:45Z",
			wantErr:   true,
		},
		{
			name:      "empty string",
			timestamp: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSigningTime(tt.timestamp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSigningTime() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !result.Equal(tt.wantTime) {
				t.Errorf("ParseSigningTime() = %v, want %v", result, tt.wantTime)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		actual   string
		want     bool
	}{
		{
			name:     "matching signatures",
			expected: "abc123",
			actual:   "abc123",
			want:     true,
		},
		{
			name:     "different signatures",
			expected: "abc123",
			actual:   "def456",
			want:     false,
		},
		{
			name:     "case sensitive",
			expected: "ABC123",
			actual:   "abc123",
			want:     false,
		},
		{
			name:     "empty signatures",
			expected: "",
			actual:   "",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifySignature(tt.expected, tt.actual)
			if result != tt.want {
				t.Errorf("VerifySignature() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestBuildCredentialScope(t *testing.T) {
	date := "20260227"
	region := "us-east-1"
	service := "myservice"

	expected := "20260227/us-east-1/myservice/aws4_request"
	result := BuildCredentialScope(date, region, service)

	if result != expected {
		t.Errorf("BuildCredentialScope() = %q, want %q", result, expected)
	}
}

func TestParseCredentialScope(t *testing.T) {
	tests := []struct {
		name        string
		scope       string
		wantDate    string
		wantRegion  string
		wantService string
		wantErr     bool
	}{
		{
			name:        "valid scope",
			scope:       "20260227/us-east-1/myservice/aws4_request",
			wantDate:    "20260227",
			wantRegion:  "us-east-1",
			wantService: "myservice",
			wantErr:     false,
		},
		{
			name:    "invalid terminator",
			scope:   "20260227/us-east-1/myservice/invalid",
			wantErr: true,
		},
		{
			name:    "too few parts",
			scope:   "20260227/us-east-1",
			wantErr: true,
		},
		{
			name:    "empty scope",
			scope:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			date, region, service, err := ParseCredentialScope(tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialScope() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if date != tt.wantDate || region != tt.wantRegion || service != tt.wantService {
					t.Errorf("ParseCredentialScope() = (%q, %q, %q), want (%q, %q, %q)",
						date, region, service, tt.wantDate, tt.wantRegion, tt.wantService)
				}
			}
		})
	}
}

func BenchmarkDeriveSigningKey(b *testing.B) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	service := "iam"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveSigningKey(secret, date, region, service)
	}
}

func BenchmarkComputeSignature(b *testing.B) {
	signingKey := []byte("test-signing-key-with-32-bytes!!")
	stringToSign := "AWS4-HMAC-SHA256\n20260227T123045Z\n20260227/us-east-1/myservice/aws4_request\nhashed-canonical-request"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeSignature(signingKey, stringToSign)
	}
}
