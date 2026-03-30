package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"secret-sync-controller/internal/auth"
)

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
	client, err := auth.NewBearerTokenFileClient(
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		10*time.Second,
	)
	if err != nil {
		return nil, err
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
