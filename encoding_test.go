package gohttpsig

import (
	"net/url"
	"testing"
)

func TestIsURIUnreserved(t *testing.T) {
	tests := []struct {
		char     byte
		expected bool
	}{
		{'A', true},
		{'Z', true},
		{'a', true},
		{'z', true},
		{'0', true},
		{'9', true},
		{'-', true},
		{'_', true},
		{'.', true},
		{'~', true},
		{'/', false},
		{' ', false},
		{'!', false},
		{'*', false},
		{'(', false},
		{')', false},
		{'%', false},
	}

	for _, tt := range tests {
		result := isURIUnreserved(tt.char)
		if result != tt.expected {
			t.Errorf("isURIUnreserved(%c) = %v, want %v", tt.char, result, tt.expected)
		}
	}
}

func TestEncodeURI(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		encodeSlash bool
		expected    string
	}{
		{
			name:        "empty path",
			path:        "",
			encodeSlash: false,
			expected:    "/",
		},
		{
			name:        "simple path",
			path:        "/path",
			encodeSlash: false,
			expected:    "/path",
		},
		{
			name:        "path with spaces",
			path:        "/path with spaces",
			encodeSlash: false,
			expected:    "/path%20with%20spaces",
		},
		{
			name:        "path with special characters",
			path:        "/path/to/file!@#$%",
			encodeSlash: false,
			expected:    "/path/to/file%21%40%23%24%25",
		},
		{
			name:        "path with unreserved characters",
			path:        "/path-with_unreserved.chars~",
			encodeSlash: false,
			expected:    "/path-with_unreserved.chars~",
		},
		{
			name:        "encode slash",
			path:        "/path/to/file",
			encodeSlash: true,
			expected:    "%2Fpath%2Fto%2Ffile",
		},
		{
			name:        "path with unicode",
			path:        "/path/文件",
			encodeSlash: false,
			expected:    "/path/%E6%96%87%E4%BB%B6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeURI(tt.path, tt.encodeSlash)
			if result != tt.expected {
				t.Errorf("EncodeURI(%q, %v) = %q, want %q", tt.path, tt.encodeSlash, result, tt.expected)
			}
		})
	}
}

func TestEncodeQueryValue(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{"simple", "simple"},
		{"with space", "with%20space"},
		{"with-dash", "with-dash"},
		{"with_underscore", "with_underscore"},
		{"with.dot", "with.dot"},
		{"with~tilde", "with~tilde"},
		{"special!@#", "special%21%40%23"},
		{"", ""},
	}

	for _, tt := range tests {
		result := EncodeQueryValue(tt.value)
		if result != tt.expected {
			t.Errorf("EncodeQueryValue(%q) = %q, want %q", tt.value, result, tt.expected)
		}
	}
}

func TestEncodeQueryValues(t *testing.T) {
	tests := []struct {
		name     string
		values   url.Values
		expected string
	}{
		{
			name:     "empty",
			values:   url.Values{},
			expected: "",
		},
		{
			name: "single parameter",
			values: url.Values{
				"key": []string{"value"},
			},
			expected: "key=value",
		},
		{
			name: "multiple parameters sorted",
			values: url.Values{
				"zebra": []string{"last"},
				"alpha": []string{"first"},
				"beta":  []string{"second"},
			},
			expected: "alpha=first&beta=second&zebra=last",
		},
		{
			name: "multiple values for same key",
			values: url.Values{
				"key": []string{"value2", "value1", "value3"},
			},
			expected: "key=value1&key=value2&key=value3",
		},
		{
			name: "special characters",
			values: url.Values{
				"key": []string{"value with spaces"},
			},
			expected: "key=value%20with%20spaces",
		},
		{
			name: "complex query",
			values: url.Values{
				"foo":   []string{"bar"},
				"baz":   []string{"qux", "quux"},
				"hello": []string{"world!"},
			},
			expected: "baz=quux&baz=qux&foo=bar&hello=world%21",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeQueryValues(tt.values)
			if result != tt.expected {
				t.Errorf("EncodeQueryValues() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "empty path",
			path:     "",
			expected: "/",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "/",
		},
		{
			name:     "simple path",
			path:     "/path/to/resource",
			expected: "/path/to/resource",
		},
		{
			name:     "redundant slashes",
			path:     "/path//to///resource",
			expected: "/path/to/resource",
		},
		{
			name:     "trailing slash preserved",
			path:     "/path/to/resource/",
			expected: "/path/to/resource/",
		},
		{
			name:     "redundant slashes with trailing",
			path:     "/path//to///resource/",
			expected: "/path/to/resource/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.path)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func BenchmarkEncodeURI(b *testing.B) {
	path := "/path/to/resource/with/some/special!@#characters"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeURI(path, false)
	}
}

func BenchmarkEncodeQueryValues(b *testing.B) {
	values := url.Values{
		"key1": []string{"value1"},
		"key2": []string{"value2", "value3"},
		"key3": []string{"value with spaces"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeQueryValues(values)
	}
}
