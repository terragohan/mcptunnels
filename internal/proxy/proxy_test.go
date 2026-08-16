package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSignIdentity(t *testing.T) {
	// Signature must match an independently computed HMAC-SHA256 over
	// "{subject}\n{email}\n{scopes}\n{client_id}".
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte("google:123\nuser@example.com\nread write\nclient-abc"))
	want := hex.EncodeToString(mac.Sum(nil))

	got := SignIdentity("s3cret", "google:123", "user@example.com", "read write", "client-abc")
	if got != want {
		t.Errorf("SignIdentity = %q, want %q", got, want)
	}
	// Different secret → different signature.
	if SignIdentity("other", "google:123", "user@example.com", "read write", "client-abc") == got {
		t.Error("signature did not change with a different secret")
	}
	// Field order matters (tampering with any field breaks the signature).
	if SignIdentity("s3cret", "user@example.com", "google:123", "read write", "client-abc") == got {
		t.Error("signature did not change with swapped fields")
	}
}

func TestRPCMethodAllowed(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		allowed bool
	}{
		{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, true},
		{"ping", `{"jsonrpc":"2.0","id":2,"method":"ping"}`, true},
		{"tools/list", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, true},
		{"tools/call denied", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"x"}}`, false},
		{"unknown method denied", `{"jsonrpc":"2.0","id":5,"method":"resources/read"}`, false},
		{"batch denied", `[{"jsonrpc":"2.0","id":1,"method":"initialize"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`, false},
		{"batch single denied", `[{"jsonrpc":"2.0","id":1,"method":"initialize"}]`, false},
		{"invalid JSON denied", `not json`, false},
		{"empty denied", ``, false},
		{"missing method denied", `{"jsonrpc":"2.0","id":6}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rpcMethodAllowed([]byte(tc.body)); got != tc.allowed {
				t.Errorf("rpcMethodAllowed(%s) = %v, want %v", tc.body, got, tc.allowed)
			}
		})
	}
}
