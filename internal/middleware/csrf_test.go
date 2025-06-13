package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFProtection(t *testing.T) {
	config := DefaultCSRFConfig()
	config.CookieSecure = false // For testing

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			// Test handler - ignore error but avoid linting issue
			return
		}
	})

	// Wrap with CSRF protection
	protectedHandler := CSRFProtect(config)(handler)

	t.Run("GET request should set CSRF token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		protectedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Check if CSRF cookie is set
		cookies := w.Result().Cookies()
		found := false
		for _, cookie := range cookies {
			if cookie.Name == config.CookieName {
				found = true
				if cookie.Value == "" {
					t.Error("CSRF token cookie is empty")
				}
				break
			}
		}
		if !found {
			t.Error("CSRF token cookie not set")
		}
	})

	t.Run("POST request without CSRF token should fail", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", bytes.NewBufferString("test=data"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		protectedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", w.Code)
		}
	})

	t.Run("POST request with valid CSRF token should succeed", func(t *testing.T) {
		// First, make a GET request to get a CSRF token
		getReq := httptest.NewRequest("GET", "/test", nil)
		getW := httptest.NewRecorder()
		protectedHandler.ServeHTTP(getW, getReq)

		// Extract CSRF token from cookie
		var csrfToken string
		cookies := getW.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == config.CookieName {
				csrfToken = cookie.Value
				break
			}
		}

		if csrfToken == "" {
			t.Fatal("Could not get CSRF token from GET request")
		}

		// Now make a POST request with the CSRF token
		postReq := httptest.NewRequest("POST", "/test", bytes.NewBufferString("test=data"))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set(config.HeaderName, csrfToken)

		// Add the CSRF cookie
		postReq.AddCookie(&http.Cookie{
			Name:  config.CookieName,
			Value: csrfToken,
		})

		postW := httptest.NewRecorder()
		protectedHandler.ServeHTTP(postW, postReq)

		if postW.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", postW.Code, postW.Body.String())
		}
	})

	t.Run("POST request with mismatched CSRF token should fail", func(t *testing.T) {
		// First, make a GET request to get a CSRF token
		getReq := httptest.NewRequest("GET", "/test", nil)
		getW := httptest.NewRecorder()
		protectedHandler.ServeHTTP(getW, getReq)

		// Extract CSRF token from cookie
		var csrfToken string
		cookies := getW.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == config.CookieName {
				csrfToken = cookie.Value
				break
			}
		}

		// Now make a POST request with a different CSRF token in header
		postReq := httptest.NewRequest("POST", "/test", bytes.NewBufferString("test=data"))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set(config.HeaderName, "wrong-token")

		// Add the correct CSRF cookie
		postReq.AddCookie(&http.Cookie{
			Name:  config.CookieName,
			Value: csrfToken,
		})

		postW := httptest.NewRecorder()
		protectedHandler.ServeHTTP(postW, postReq)

		if postW.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", postW.Code)
		}
	})
}

func TestGenerateCSRFToken(t *testing.T) {
	token1, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("Error generating CSRF token: %v", err)
	}

	token2, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("Error generating CSRF token: %v", err)
	}

	if token1 == token2 {
		t.Error("Generated tokens should be unique")
	}

	if len(token1) == 0 {
		t.Error("Generated token should not be empty")
	}
}

func TestValidateCSRFToken(t *testing.T) {
	token1 := "test-token-123"
	token2 := "test-token-123"
	token3 := "different-token"

	if !validateCSRFToken(token1, token2) {
		t.Error("Identical tokens should validate")
	}

	if validateCSRFToken(token1, token3) {
		t.Error("Different tokens should not validate")
	}
}
