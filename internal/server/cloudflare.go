package server

import (
	"net"
	"net/http"
	"strings"
)

// CloudflareClientIP trusts CF-Connecting-IP only when the operator has
// configured the daemon to run exclusively behind Cloudflare.
func CloudflareClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); ip != nil {
			r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
		}
		next.ServeHTTP(w, r)
	})
}
