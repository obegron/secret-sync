package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseIssuerMapping(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIss string
		wantURL string
		wantErr bool
	}{
		{
			name:    "simple mapping",
			input:   "https://issuer.example.com=https://discovery.example.com",
			wantIss: "https://issuer.example.com",
			wantURL: "https://discovery.example.com",
		},
		{
			name:    "same issuer and discovery",
			input:   "https://issuer.example.com",
			wantIss: "https://issuer.example.com",
			wantURL: "https://issuer.example.com",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "too many equals",
			input:   "a=b=c",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iss, url, err := ParseIssuerMapping(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseIssuerMapping() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if iss != tt.wantIss {
				t.Fatalf("ParseIssuerMapping() issuer = %q, want %q", iss, tt.wantIss)
			}
			if url != tt.wantURL {
				t.Fatalf("ParseIssuerMapping() url = %q, want %q", url, tt.wantURL)
			}
		})
	}
}

func TestParseJWK_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	parsed, err := ParseJWK(jwkFromRSA("test-key", &key.PublicKey))
	if err != nil {
		t.Fatalf("ParseJWK() error = %v", err)
	}

	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("ParseJWK() type = %T, want *rsa.PublicKey", parsed)
	}
	if rsaKey.E != 65537 {
		t.Fatalf("ParseJWK() exponent = %d, want 65537", rsaKey.E)
	}
	if rsaKey.N.Cmp(key.PublicKey.N) != 0 {
		t.Fatal("ParseJWK() modulus mismatch")
	}
}

func TestVerifierAuthenticateRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	const issuer = "https://issuer.example.com"
	const kid = "test-key"
	const subject = "system:serviceaccount:secret-sync-vcluster-system:secret-sync-controller"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(OpenIDConfig{
				Issuer:  issuer,
				JWKSURI: serverURL(t, r) + "/openid/v1/jwks",
			})
		case "/openid/v1/jwks":
			_ = json.NewEncoder(w).Encode(JWKS{
				Keys: []JWK{jwkFromRSA(kid, &privateKey.PublicKey)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	verifier, err := NewVerifier([]string{issuer + "=" + server.URL}, map[string]struct{}{subject: {}})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	validToken := signedToken(t, privateKey, kid, issuer, subject, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "http://bridge.test/bridge/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)

	claims, err := verifier.AuthenticateRequest(req)
	if err != nil {
		t.Fatalf("AuthenticateRequest() error = %v", err)
	}
	if claims.Subject != subject {
		t.Fatalf("AuthenticateRequest() subject = %q, want %q", claims.Subject, subject)
	}

	t.Run("wrong subject", func(t *testing.T) {
		badToken := signedToken(t, privateKey, kid, issuer, "system:serviceaccount:other:sa", time.Now().Add(time.Hour))
		req := httptest.NewRequest(http.MethodGet, "http://bridge.test/bridge/v1/secrets", nil)
		req.Header.Set("Authorization", "Bearer "+badToken)
		if _, err := verifier.AuthenticateRequest(req); err == nil {
			t.Fatal("AuthenticateRequest() expected subject rejection")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		badToken := signedToken(t, privateKey, kid, "https://wrong-issuer.example.com", subject, time.Now().Add(time.Hour))
		req := httptest.NewRequest(http.MethodGet, "http://bridge.test/bridge/v1/secrets", nil)
		req.Header.Set("Authorization", "Bearer "+badToken)
		if _, err := verifier.AuthenticateRequest(req); err == nil {
			t.Fatal("AuthenticateRequest() expected issuer rejection")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		expiredToken := signedToken(t, privateKey, kid, issuer, subject, time.Now().Add(-time.Hour))
		req := httptest.NewRequest(http.MethodGet, "http://bridge.test/bridge/v1/secrets", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		if _, err := verifier.AuthenticateRequest(req); err == nil {
			t.Fatal("AuthenticateRequest() expected expiration rejection")
		}
	})
}

func TestVerifierDiscoveryFailures(t *testing.T) {
	const issuer = "https://issuer.example.com"

	t.Run("issuer mismatch from discovery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_ = json.NewEncoder(w).Encode(OpenIDConfig{
					Issuer:  "https://wrong-issuer.example.com",
					JWKSURI: serverURL(t, r) + "/openid/v1/jwks",
				})
			case "/openid/v1/jwks":
				_ = json.NewEncoder(w).Encode(JWKS{})
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		verifier, err := NewVerifier([]string{issuer + "=" + server.URL}, nil)
		if err != nil {
			t.Fatalf("NewVerifier() error = %v", err)
		}

		err = verifier.refreshKeys(issuer)
		if err == nil {
			t.Fatal("refreshKeys() expected issuer mismatch error")
		}
	})

	t.Run("jwks status failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_ = json.NewEncoder(w).Encode(OpenIDConfig{
					Issuer:  issuer,
					JWKSURI: serverURL(t, r) + "/openid/v1/jwks",
				})
			case "/openid/v1/jwks":
				http.Error(w, "nope", http.StatusBadGateway)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		verifier, err := NewVerifier([]string{issuer + "=" + server.URL}, nil)
		if err != nil {
			t.Fatalf("NewVerifier() error = %v", err)
		}

		err = verifier.refreshKeys(issuer)
		if err == nil {
			t.Fatal("refreshKeys() expected jwks failure")
		}
	})
}

func signedToken(t *testing.T, privateKey *rsa.PrivateKey, kid, issuer, subject string, expiry time.Time) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(expiry),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	})
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return tokenString
}

func jwkFromRSA(kid string, key *rsa.PublicKey) JWK {
	return JWK{
		Kid: kid,
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func serverURL(t *testing.T, r *http.Request) string {
	t.Helper()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
