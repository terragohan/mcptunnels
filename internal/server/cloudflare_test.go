package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/terragohan/mcptunnels/internal/server"
)

func TestCloudflareClientIP(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		remoteAddr string
		want       string
	}{
		{name: "ipv4", header: "203.0.113.10", remoteAddr: "10.0.0.1:1234", want: "203.0.113.10:0"},
		{name: "ipv6", header: " 2001:db8::1 ", remoteAddr: "10.0.0.1:1234", want: "[2001:db8::1]:0"},
		{name: "missing", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1:1234"},
		{name: "invalid", header: "not-an-ip", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1:1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			handler := server.CloudflareClientIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.header != "" {
				req.Header.Set("CF-Connecting-IP", tt.header)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if got != tt.want {
				t.Fatalf("RemoteAddr = %q, want %q", got, tt.want)
			}
		})
	}
}
