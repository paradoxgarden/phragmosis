package main

import (
	//"net/http/httptest"
	"testing"
)

func TestVerifyRedirect(t *testing.T) {
	tests := []struct {
		name     string
		redirect string
		domain   string
		want     bool
	}{
		{"happy path", "example.com/reallycoolcat.jpeg", "example.com", true},
		{"happy path relative", "/reallycoolcat.jpeg", "example.com", true},
		{"happy path subdomain", "auth.example.com", "example.com", true},
		{"other domain", "bsky.app", "example.com", false},
		{"http", "http://example.com/reallycoolcat.jpeg", "example.com", false},
		{"bad url", "auth.e@xamepl.com", "example.com", false},
		{"path redirect", "//im/in/your/files", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := verifyRedirect(tt.redirect, tt.domain)
			if got != tt.want {
				t.Errorf("verifyRedirect(%q) for %v, want %v", tt.redirect, tt.domain, tt.want)
			}
		})
	}
}

func TestAuthHandler(t *testing.T){
	//req := httptest.NewRequest("GET","/", nil)
	//w := httptest.NewRecorder()
}
