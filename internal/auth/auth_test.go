package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "successfully extracts API key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-key-123"}},
			expectedKey:   "test-key-123",
			expectedError: nil,
		},
		{
			name:          "returns error when no auth header included",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "returns error when authorization header is empty",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "returns error when authorization header is malformed (no space)",
			headers:       http.Header{"Authorization": []string{"ApiKeytest-key-123"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "returns error when authorization header is malformed (wrong prefix)",
			headers:       http.Header{"Authorization": []string{"Bearer test-key-123"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check error
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}

			// Check error is nil when expected
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			// Check returned key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
