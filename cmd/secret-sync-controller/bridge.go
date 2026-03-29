package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type bridgeSecretList struct {
	Items []bridgeSecret `json:"items"`
}

type bridgeSecret struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Type        corev1.SecretType `json:"type"`
	Data        map[string][]byte `json:"data,omitempty"`
	Immutable   *bool             `json:"immutable,omitempty"`
}

func (b bridgeSecret) toSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   b.Namespace,
			Name:        b.Name,
			Labels:      b.Labels,
			Annotations: b.Annotations,
		},
		Type:      b.Type,
		Data:      b.Data,
		Immutable: b.Immutable,
	}
}

func bridgeSecretFromCore(secret *corev1.Secret) bridgeSecret {
	return bridgeSecret{
		Namespace:   secret.Namespace,
		Name:        secret.Name,
		Labels:      secret.Labels,
		Annotations: secret.Annotations,
		Type:        secret.Type,
		Data:        secret.Data,
		Immutable:   secret.Immutable,
	}
}

func (c *controller) runPullBridge(ctx context.Context) {
	known := map[string]*corev1.Secret{}
	for {
		next, err := c.syncBridgePull(ctx, known)
		if err != nil {
			c.metrics.reconcileErrors.Add(1)
			log.Printf("bridge pull sync failed: %v", err)
		} else {
			known = next
			c.ready.Store(true)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(c.cfg.bridgePollInterval):
		}
	}
}

func (c *controller) syncBridgePull(ctx context.Context, previous map[string]*corev1.Secret) (map[string]*corev1.Secret, error) {
	secrets, err := c.fetchBridgeSecrets(ctx)
	if err != nil {
		return previous, err
	}

	current := make(map[string]*corev1.Secret, len(secrets))
	var errs []string
	for _, src := range secrets {
		key := fmt.Sprintf("%s/%s", src.Namespace, src.Name)
		current[key] = src.DeepCopy()
		if reconcileErr := c.reconcilePull(ctx, src); reconcileErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", key, reconcileErr))
		}
	}

	for key, prev := range previous {
		if _, ok := current[key]; ok {
			continue
		}
		if deleteErr := c.handleDeletePull(ctx, prev); deleteErr != nil {
			errs = append(errs, fmt.Sprintf("%s delete: %v", key, deleteErr))
		}
	}

	if len(errs) > 0 {
		return current, errors.New(strings.Join(errs, "; "))
	}

	return current, nil
}

func (c *controller) fetchBridgeSecrets(ctx context.Context) ([]*corev1.Secret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.cfg.bridgeBaseURL, "/")+"/bridge/v1/secrets", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.bridgeHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("bridge endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload bridgeSecretList
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	result := make([]*corev1.Secret, 0, len(payload.Items))
	for _, item := range payload.Items {
		result = append(result, item.toSecret())
	}
	return result, nil
}

func (c *controller) handleBridgeList(w http.ResponseWriter, r *http.Request) {
	if c.cfg.syncMode != modeSource {
		http.NotFound(w, r)
		return
	}
	if c.bridgeVerifier == nil {
		http.Error(w, "bridge verifier is not configured\n", http.StatusInternalServerError)
		return
	}
	if _, err := c.bridgeVerifier.authenticate(r); err != nil {
		http.Error(w, err.Error()+"\n", http.StatusUnauthorized)
		return
	}

	secrets, err := c.hostClient.CoreV1().Secrets(c.cfg.sourceNamespace).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, err.Error()+"\n", http.StatusBadGateway)
		return
	}

	payload := bridgeSecretList{Items: make([]bridgeSecret, 0, len(secrets.Items))}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if secret.Labels[labelSyncEnabled] != "true" {
			continue
		}
		payload.Items = append(payload.Items, bridgeSecretFromCore(secret))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

type bridgeVerifier struct {
	issuerMap       map[string][]string
	allowedSubjects map[string]struct{}
	keys            map[string]interface{}
	mu              sync.RWMutex
}

type openIDConfig struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func newBridgeVerifier(issuerMappings []string, allowedSubjects map[string]struct{}) (*bridgeVerifier, error) {
	if len(issuerMappings) == 0 {
		return nil, errors.New("at least one BRIDGE_TRUST_ISSUERS entry is required")
	}

	issuerMap := make(map[string][]string, len(issuerMappings))
	for _, raw := range issuerMappings {
		issuer, discoveryURL, err := parseIssuerMapping(raw)
		if err != nil {
			return nil, err
		}
		issuerMap[issuer] = append(issuerMap[issuer], discoveryURL)
	}

	return &bridgeVerifier{
		issuerMap:       issuerMap,
		allowedSubjects: allowedSubjects,
		keys:            map[string]interface{}{},
	}, nil
}

func parseIssuerMapping(raw string) (string, string, error) {
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

func (v *bridgeVerifier) authenticate(r *http.Request) (*jwt.RegisteredClaims, error) {
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

func (v *bridgeVerifier) keyFunc(token *jwt.Token) (interface{}, error) {
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

func (v *bridgeVerifier) refreshKeys(issuer string) error {
	discoveryURLs, ok := v.issuerMap[issuer]
	if !ok {
		return fmt.Errorf("unknown issuer %q", issuer)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var allKeys []jwk
	var lastErr error
	for _, discoveryURL := range discoveryURLs {
		configURL := strings.TrimSuffix(discoveryURL, "/") + "/.well-known/openid-configuration"
		resp, err := client.Get(configURL)
		if err != nil {
			lastErr = err
			continue
		}
		var cfg openIDConfig
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
		var payload jwks
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
		pubKey, err := parseJWK(item)
		if err != nil {
			log.Printf("ignore unsupported JWK %q for issuer %s: %v", item.Kid, issuer, err)
			continue
		}
		v.keys[issuer+"|"+item.Kid] = pubKey
	}
	return nil
}

func parseJWK(item jwk) (interface{}, error) {
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

func newBridgeHTTPClient(caFile, tokenFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(caFile) != "" {
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("append bridge CA from %q failed", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &bridgeAuthTransport{
			tokenFile:  tokenFile,
			underlying: transport,
		},
	}, nil
}

type bridgeAuthTransport struct {
	tokenFile  string
	underlying http.RoundTripper
}

func (t *bridgeAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tokenBytes, err := os.ReadFile(t.tokenFile)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenBytes)))
	return t.underlying.RoundTrip(clone)
}

func (c *controller) handleOIDCConfigProxy(w http.ResponseWriter, r *http.Request) {
	if !c.cfg.oidcProxyEnabled {
		http.NotFound(w, r)
		return
	}
	body, err := c.fetchLocalOIDCPath(r.Context(), "/.well-known/openid-configuration")
	if err != nil {
		http.Error(w, err.Error()+"\n", http.StatusBadGateway)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, err.Error()+"\n", http.StatusInternalServerError)
		return
	}
	payload["jwks_uri"] = strings.TrimSuffix(c.oidcProxyBaseURL(r), "/") + "/openid/v1/jwks"

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (c *controller) handleJWKSProxy(w http.ResponseWriter, r *http.Request) {
	if !c.cfg.oidcProxyEnabled {
		http.NotFound(w, r)
		return
	}
	body, err := c.fetchLocalOIDCPath(r.Context(), "/openid/v1/jwks")
	if err != nil {
		http.Error(w, err.Error()+"\n", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (c *controller) oidcProxyBaseURL(r *http.Request) string {
	if strings.TrimSpace(c.cfg.oidcProxyBaseURL) != "" {
		return c.cfg.oidcProxyBaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (c *controller) fetchLocalOIDCPath(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(localKubernetesAPIBase(), "/")+path, nil)
	if err != nil {
		return nil, err
	}
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenBytes)))

	caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("append OIDC proxy CA failed")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("local oidc upstream returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func localKubernetesAPIBase() string {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return ""
	}
	return "https://" + host + ":" + port
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}

func splitCSVSet(raw string) map[string]struct{} {
	parts := splitCSV(raw)
	if len(parts) == 0 {
		return nil
	}
	result := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		result[part] = struct{}{}
	}
	return result
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	return time.ParseDuration(raw)
}
