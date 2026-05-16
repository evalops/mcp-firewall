package main

import "testing"

func TestParseHeadersSupportsEqualsValuesWithColons(t *testing.T) {
	headers := parseHeaders([]string{
		"Authorization: Bearer token",
		"X-Forward=http://internal:8080/path",
	})

	if headers["Authorization"] != "Bearer token" {
		t.Fatalf("Authorization header = %q", headers["Authorization"])
	}
	if headers["X-Forward"] != "http://internal:8080/path" {
		t.Fatalf("X-Forward header = %q", headers["X-Forward"])
	}
}
