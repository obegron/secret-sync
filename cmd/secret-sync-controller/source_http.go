package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *controller) handleBridgeList(w http.ResponseWriter, r *http.Request) {
	if c.cfg.syncMode != modeSource {
		http.NotFound(w, r)
		return
	}
	if err := c.authenticateProtectedSourceRequest(r); err != nil {
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
			c.logVerbosef("skip bridge source secret=%s/%s: %s is %q", secret.Namespace, secret.Name, labelSyncEnabled, secret.Labels[labelSyncEnabled])
			continue
		}
		payload.Items = append(payload.Items, bridgeSecretFromCore(secret))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (c *controller) handleVClusterKubeconfig(w http.ResponseWriter, r *http.Request) {
	if c.cfg.syncMode != modeSource {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(c.cfg.kubeconfigSecretName) == "" {
		http.Error(w, "kubeconfig secret is not configured\n", http.StatusServiceUnavailable)
		return
	}
	if err := c.authenticateProtectedSourceRequest(r); err != nil {
		http.Error(w, err.Error()+"\n", http.StatusUnauthorized)
		return
	}

	secret, err := c.hostClient.CoreV1().Secrets(c.cfg.sourceNamespace).Get(r.Context(), c.cfg.kubeconfigSecretName, metav1.GetOptions{})
	if err != nil {
		http.Error(w, "failed to read kubeconfig secret\n", http.StatusBadGateway)
		return
	}
	data, ok := secret.Data[c.cfg.kubeconfigSecretKey]
	if !ok {
		http.Error(w, "kubeconfig key is missing\n", http.StatusBadGateway)
		return
	}
	if len(data) == 0 {
		http.Error(w, "kubeconfig key is empty\n", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="kubeconfig.yaml"`)
	_, _ = w.Write(data)
}

func (c *controller) authenticateProtectedSourceRequest(r *http.Request) error {
	if c.bridgeVerifier == nil {
		return errors.New("request verifier is not configured")
	}
	_, err := c.bridgeVerifier.AuthenticateRequest(r)
	return err
}
