package middleware

import (
	"context"
	"net/http"
)

type cspNonceKey struct{}

// SetCSPNonce stores the CSP nonce in the request context
func SetCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceKey{}, nonce)
}

// GetCSPNonce retrieves the CSP nonce from the request context
func GetCSPNonce(ctx context.Context) string {
	if nonce, ok := ctx.Value(cspNonceKey{}).(string); ok {
		return nonce
	}
	return ""
}

// GetCSPNonceFromRequest is a convenience function to get nonce from http.Request
func GetCSPNonceFromRequest(r *http.Request) string {
	return GetCSPNonce(r.Context())
}
