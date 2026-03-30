package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"secret-sync-controller/internal/auth"
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
		start := time.Now()
		next, err := c.syncBridgePull(ctx, known)
		if err != nil {
			c.metrics.reconcileErrors.Add(1)
			c.metrics.bridgePollErrors.Add(1)
			c.recordError("bridge_poll_failed")
			c.logVerbosef("bridge poll failed baseURL=%s: %v", c.cfg.bridgeBaseURL, err)
			log.Printf("bridge pull sync failed: %v", err)
		} else {
			known = next
			c.metrics.bridgePollSuccess.Add(1)
			c.recordSuccess(time.Since(start))
			c.logVerbosef("bridge poll succeeded baseURL=%s secrets=%d", c.cfg.bridgeBaseURL, len(next))
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

func newBridgeHTTPClient(caFile, tokenFile string) (*http.Client, error) {
	return auth.NewBearerTokenFileClient(tokenFile, caFile, 15*time.Second)
}
