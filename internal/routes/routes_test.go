package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/o4f6bgpac3/template/internal/middleware"
)

func TestNonceInjection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		nonce    string
		expected string
	}{
		{
			name:     "InlineScriptWithoutNonce",
			input:    `<script>console.log("test");</script>`,
			nonce:    "test-nonce-123",
			expected: `<script nonce="test-nonce-123">console.log("test");</script>`,
		},
		{
			name:     "ScriptWithAttributesWithoutNonce",
			input:    `<script type="text/javascript">alert('hello');</script>`,
			nonce:    "abc123",
			expected: `<script type="text/javascript" nonce="abc123">alert('hello');</script>`,
		},
		{
			name:     "ScriptAlreadyHasNonce",
			input:    `<script nonce="existing-nonce">console.log("test");</script>`,
			nonce:    "new-nonce",
			expected: `<script nonce="existing-nonce">console.log("test");</script>`,
		},
		{
			name:     "MultipleScripts",
			input:    `<script>first();</script><script>second();</script>`,
			nonce:    "multi-nonce",
			expected: `<script nonce="multi-nonce">first();</script><script nonce="multi-nonce">second();</script>`,
		},
		{
			name:     "ComplexHTMLWithScript",
			input:    `<html><head><script>console.log("init");</script></head><body><p>content</p></body></html>`,
			nonce:    "complex-nonce",
			expected: `<html><head><script nonce="complex-nonce">console.log("init");</script></head><body><p>content</p></body></html>`,
		},
		{
			name:     "SvelteKitGeneratedScript",
			input: `<script>
				{
					__sveltekit_1857p90 = {
						base: ""
					};

					const element = document.currentScript.parentElement;

					Promise.all([
						import("/_app/immutable/entry/start.nIKmrFkP.js"),
						import("/_app/immutable/entry/app.Bs8U8QMz.js")
					]).then(([kit, app]) => {
						kit.start(app, element);
					});
				}
			</script>`,
			nonce: "svelte-nonce",
			expected: `<script nonce="svelte-nonce">
				{
					__sveltekit_1857p90 = {
						base: ""
					};

					const element = document.currentScript.parentElement;

					Promise.all([
						import("/_app/immutable/entry/start.nIKmrFkP.js"),
						import("/_app/immutable/entry/app.Bs8U8QMz.js")
					]).then(([kit, app]) => {
						kit.start(app, element);
					});
				}
			</script>`,
		},
		{
			name:     "NoScriptTags",
			input:    `<html><body><p>No scripts here</p></body></html>`,
			nonce:    "no-script-nonce",
			expected: `<html><body><p>No scripts here</p></body></html>`,
		},
		{
			name:     "EmptyNonce",
			input:    `<script>console.log("test");</script>`,
			nonce:    "",
			expected: `<script>console.log("test");</script>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.nonce != "" {
				ctx := middleware.SetCSPNonce(req.Context(), tt.nonce)
				req = req.WithContext(ctx)
			}

			result := injectNonceIntoHTML(tt.input, req)

			if result != tt.expected {
				t.Errorf("injectNonceIntoHTML() failed\nInput:    %s\nExpected: %s\nGot:      %s", tt.input, tt.expected, result)
			}
		})
	}
}

func TestNonceInjectionSecurityProperties(t *testing.T) {
	t.Run("NonceInjectionPreservesExistingNonces", func(t *testing.T) {
		input := `<script nonce="original">safe();</script><script>unsafe();</script>`
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := middleware.SetCSPNonce(req.Context(), "new-nonce")
		req = req.WithContext(ctx)

		result := injectNonceIntoHTML(input, req)

		// Original nonce should be preserved
		if !strings.Contains(result, `nonce="original"`) {
			t.Error("Original nonce should be preserved")
		}

		// New nonce should be added to script without nonce
		if !strings.Contains(result, `nonce="new-nonce"`) {
			t.Error("New nonce should be added to script without nonce")
		}

		expected := `<script nonce="original">safe();</script><script nonce="new-nonce">unsafe();</script>`
		if result != expected {
			t.Errorf("Expected: %s\nGot: %s", expected, result)
		}
	})

	t.Run("NonceInjectionIsCSPCompliant", func(t *testing.T) {
		input := `<script>console.log("test");</script>`
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := middleware.SetCSPNonce(req.Context(), "secure-nonce-123")
		req = req.WithContext(ctx)

		result := injectNonceIntoHTML(input, req)

		// Result should be CSP compliant
		expected := `<script nonce="secure-nonce-123">console.log("test");</script>`
		if result != expected {
			t.Errorf("Expected CSP compliant output: %s\nGot: %s", expected, result)
		}

		// Verify the nonce format is correct
		if !strings.Contains(result, `nonce="secure-nonce-123"`) {
			t.Error("Nonce should be properly formatted for CSP compliance")
		}
	})
}

func TestSecurityDocumentation(t *testing.T) {
	t.Run("NonceInjectionSecurityDocumentation", func(t *testing.T) {
		t.Log("=== Nonce Injection Security Documentation ===")
		t.Log("")
		t.Log("VULNERABILITY: Static HTML with Inline Scripts")
		t.Log("- SvelteKit generates static HTML with inline scripts")
		t.Log("- CSP requires nonces for inline scripts to prevent XSS")
		t.Log("- Static files cannot contain dynamic nonces")
		t.Log("")
		t.Log("MITIGATION: Dynamic Nonce Injection")
		t.Log("- injectNonceIntoHTML() adds nonces to inline scripts dynamically")
		t.Log("- Preserves existing nonces to avoid breaking CSP")
		t.Log("- Works with SvelteKit-generated inline scripts")
		t.Log("- Fails securely when nonce is unavailable")
		t.Log("")
		t.Log("VERIFICATION:")
		t.Log("- Test nonce injection with various HTML structures")
		t.Log("- Verify CSP compliance of generated HTML")
		t.Log("- Confirm existing nonces are preserved")
		t.Log("")
		t.Log("SECURITY PROPERTY:")
		t.Log("∀ inline scripts s: nonce(s) ∈ {existing_nonce, current_request_nonce}")
	})
}