package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	issuerMap       map[string][]string
	allowedSubjects map[string]struct{}
	keys            map[string]interface{}
	mu              sync.RWMutex
}

type OpenIDConfig struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewVerifier(issuerMappings []string, allowedSubjects map[string]struct{}) (*Verifier, error) {
	if len(issuerMappings) == 0 {
		return nil, errors.New("at least one issuer mapping is required")
	}

	issuerMap := make(map[string][]string, len(issuerMappings))
	for _, raw := range issuerMappings {
		issuer, discoveryURL, err := ParseIssuerMapping(raw)
		if err != nil {
			return nil, err
		}
		issuerMap[issuer] = append(issuerMap[issuer], discoveryURL)
	}

	return &Verifier{
		issuerMap:       issuerMap,
		allowedSubjects: allowedSubjects,
		keys:            map[string]interface{}{},
	}, nil
}

func ParseIssuerMapping(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("empty issuer mapping")
	}
	parts := strings.Split(raw, "=")
	switch len(parts) {
	case 1:
		return raw, raw, nil
	case 2:
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	default:
		return "", "", fmt.Errorf("invalid issuer mapping %q", raw)
	}
}

func (v *Verifier) AuthenticateRequest(r *http.Request) (*jwt.RegisteredClaims, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return nil, errors.New("missing bearer token")
	}
	tokenString := strings.TrimSpace(header[len("Bearer "):])
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, v.keyFunc, jwt.WithValidMethods([]string{"RS256", "ES256", "ES384", "ES512"}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	if _, ok := v.issuerMap[claims.Issuer]; !ok {
		return nil, fmt.Errorf("untrusted issuer %q", claims.Issuer)
	}
	if len(v.allowedSubjects) > 0 {
		if _, ok := v.allowedSubjects[claims.Subject]; !ok {
			return nil, fmt.Errorf("subject %q is not allowed", claims.Subject)
		}
	}
	return claims, nil
}

func (v *Verifier) keyFunc(token *jwt.Token) (interface{}, error) {
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}
	if _, trusted := v.issuerMap[claims.Issuer]; !trusted {
		return nil, fmt.Errorf("untrusted issuer %q", claims.Issuer)
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(kid) == "" {
		return nil, errors.New("missing kid in token header")
	}
	keyID := claims.Issuer + "|" + kid
	v.mu.RLock()
	key := v.keys[keyID]
	v.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	if err := v.refreshKeys(claims.Issuer); err != nil {
		return nil, err
	}
	v.mu.RLock()
	key = v.keys[keyID]
	v.mu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("key not found for issuer %q kid %q", claims.Issuer, kid)
	}
	return key, nil
}

func (v *Verifier) refreshKeys(issuer string) error {
	discoveryURLs, ok := v.issuerMap[issuer]
	if !ok {
		return fmt.Errorf("unknown issuer %q", issuer)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var allKeys []JWK
	var lastErr error
	for _, discoveryURL := range discoveryURLs {
		configURL := strings.TrimSuffix(discoveryURL, "/") + "/.well-known/openid-configuration"
		resp, err := client.Get(configURL)
		if err != nil {
			lastErr = err
			continue
		}
		var cfg OpenIDConfig
		if resp.StatusCode == http.StatusOK {
			err = json.NewDecoder(resp.Body).Decode(&cfg)
		} else {
			err = fmt.Errorf("discovery status %d", resp.StatusCode)
		}
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if strings.TrimSpace(cfg.Issuer) != issuer {
			lastErr = fmt.Errorf("issuer mismatch from discovery %q: expected %q got %q", discoveryURL, issuer, cfg.Issuer)
			continue
		}

		jwksResp, err := client.Get(cfg.JWKSURI)
		if err != nil {
			lastErr = err
			continue
		}
		var payload JWKS
		if jwksResp.StatusCode == http.StatusOK {
			err = json.NewDecoder(jwksResp.Body).Decode(&payload)
		} else {
			err = fmt.Errorf("jwks status %d", jwksResp.StatusCode)
		}
		jwksResp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		allKeys = append(allKeys, payload.Keys...)
	}
	if len(allKeys) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no keys fetched")
		}
		return lastErr
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	for _, item := range allKeys {
		pubKey, err := ParseJWK(item)
		if err != nil {
			log.Printf("ignore unsupported JWK %q for issuer %s: %v", item.Kid, issuer, err)
			continue
		}
		v.keys[issuer+"|"+item.Kid] = pubKey
	}
	return nil
}

func ParseJWK(item JWK) (interface{}, error) {
	switch item.Kty {
	case "RSA":
		return parseRSAPublicKey(item.N, item.E)
	case "EC":
		return parseECPublicKey(item.Crv, item.X, item.Y)
	default:
		return nil, fmt.Errorf("unsupported kty %q", item.Kty)
	}
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	eInt := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(eInt.Int64())}, nil
}

func parseECPublicKey(crv, xStr, yStr string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
