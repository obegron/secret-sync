package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type runtimeConfig struct {
	syncMode               string
	sourceProvider         string
	logVerbose             bool
	logReconcileActions    bool
	kubeconfigSecretName   string
	kubeconfigSecretKey    string
	hostKubeconfig         string
	hostAPIServer          string
	hostTokenFile          string
	hostCAFile             string
	podNamespace           string
	sourceNamespace        string
	targetNamespace        string
	defaultDeletePolicy    string
	metricsBindAddress     string
	pullNamespaceIsolation bool
	bridgeBaseURL          string
	bridgeTokenFile        string
	bridgeCAFile           string
	bridgePollInterval     time.Duration
	bridgeTrustIssuers     []string
	bridgeAllowedSubjects  map[string]struct{}
	oidcProxyEnabled       bool
	oidcProxyBaseURL       string
}

func loadRuntimeConfig() (runtimeConfig, map[string]struct{}, error) {
	syncMode := strings.ToLower(strings.TrimSpace(envOrDefault("SYNC_MODE", modePush)))
	if syncMode != modePush && syncMode != modePull && syncMode != modeSource {
		return runtimeConfig{}, nil, fmt.Errorf("invalid SYNC_MODE %q (expected %q, %q or %q)", syncMode, modePush, modePull, modeSource)
	}

	sourceProvider := strings.ToLower(strings.TrimSpace(envOrDefault("SOURCE_PROVIDER", sourceProviderKubernetes)))
	if sourceProvider != sourceProviderKubernetes && sourceProvider != sourceProviderBridge {
		return runtimeConfig{}, nil, fmt.Errorf("invalid SOURCE_PROVIDER %q (expected %q or %q)", sourceProvider, sourceProviderKubernetes, sourceProviderBridge)
	}

	pullNamespaceIsolation, err := parseBoolEnv("PULL_NAMESPACE_ISOLATION", false)
	if err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("invalid PULL_NAMESPACE_ISOLATION: %w", err)
	}

	podNamespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	sourceNamespace := strings.TrimSpace(os.Getenv("SOURCE_NAMESPACE"))
	if sourceNamespace == "" && pullNamespaceIsolation {
		sourceNamespace = podNamespace
	}

	if pullNamespaceIsolation && sourceNamespace == "" {
		return runtimeConfig{}, nil, errors.New("PULL_NAMESPACE_ISOLATION requires SOURCE_NAMESPACE (or POD_NAMESPACE)")
	}
	if pullNamespaceIsolation && podNamespace != "" && sourceNamespace != podNamespace {
		return runtimeConfig{}, nil, fmt.Errorf("PULL_NAMESPACE_ISOLATION requires SOURCE_NAMESPACE (%q) to match POD_NAMESPACE (%q)", sourceNamespace, podNamespace)
	}

	allowedTargetIDs, err := parseAllowedTargetIDs(os.Getenv("ALLOWED_SYNC_TARGETS"))
	if err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("invalid ALLOWED_SYNC_TARGETS: %w", err)
	}

	cfg := runtimeConfig{
		syncMode:               syncMode,
		sourceProvider:         sourceProvider,
		kubeconfigSecretName:   strings.TrimSpace(os.Getenv("KUBECONFIG_SECRET_NAME")),
		kubeconfigSecretKey:    envOrDefault("KUBECONFIG_SECRET_KEY", "config"),
		hostKubeconfig:         os.Getenv("HOST_KUBECONFIG"),
		hostAPIServer:          strings.TrimSpace(os.Getenv("HOST_API_SERVER")),
		hostTokenFile:          envOrDefault("HOST_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		hostCAFile:             envOrDefault("HOST_CA_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
		podNamespace:           podNamespace,
		sourceNamespace:        sourceNamespace,
		targetNamespace:        strings.TrimSpace(os.Getenv("TARGET_NAMESPACE")),
		defaultDeletePolicy:    normalizeDeletePolicy(envOrDefault("DEFAULT_DELETE_POLICY", "delete")),
		metricsBindAddress:     envOrDefault("METRICS_BIND_ADDRESS", ":8080"),
		pullNamespaceIsolation: pullNamespaceIsolation,
		bridgeBaseURL:          strings.TrimSpace(os.Getenv("BRIDGE_BASE_URL")),
		bridgeTokenFile:        envOrDefault("BRIDGE_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		bridgeCAFile:           strings.TrimSpace(os.Getenv("BRIDGE_CA_FILE")),
		bridgeTrustIssuers:     splitCSV(os.Getenv("BRIDGE_TRUST_ISSUERS")),
		bridgeAllowedSubjects:  splitCSVSet(os.Getenv("BRIDGE_ALLOWED_SUBJECTS")),
		oidcProxyBaseURL:       strings.TrimSpace(os.Getenv("OIDC_PROXY_BASE_URL")),
	}

	cfg.logReconcileActions, err = parseBoolEnv("LOG_RECONCILE_ACTIONS", false)
	if err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("invalid LOG_RECONCILE_ACTIONS: %w", err)
	}
	cfg.logVerbose, err = parseBoolEnv("LOG_VERBOSE", false)
	if err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("invalid LOG_VERBOSE: %w", err)
	}
	cfg.oidcProxyEnabled, err = parseBoolEnv("OIDC_PROXY_ENABLED", false)
	if err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("invalid OIDC_PROXY_ENABLED: %w", err)
	}
	cfg.bridgePollInterval, err = parseDurationEnv("BRIDGE_POLL_INTERVAL", 15*time.Second)
	if err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("invalid BRIDGE_POLL_INTERVAL: %w", err)
	}

	if cfg.targetNamespace == "" {
		cfg.targetNamespace = cfg.podNamespace
	}
	if (cfg.syncMode == modePull || cfg.syncMode == modeSource) && strings.TrimSpace(cfg.sourceNamespace) == "" {
		return runtimeConfig{}, nil, errors.New("SYNC_MODE=pull or SYNC_MODE=source requires SOURCE_NAMESPACE")
	}
	if cfg.syncMode == modePull && strings.TrimSpace(cfg.targetNamespace) == "" {
		return runtimeConfig{}, nil, errors.New("SYNC_MODE=pull requires TARGET_NAMESPACE or POD_NAMESPACE")
	}
	if cfg.syncMode == modePull && cfg.sourceProvider == sourceProviderBridge && cfg.bridgeBaseURL == "" {
		return runtimeConfig{}, nil, errors.New("SOURCE_PROVIDER=bridge requires BRIDGE_BASE_URL")
	}
	if cfg.syncMode == modePull && cfg.sourceNamespace == cfg.targetNamespace && cfg.hostAPIServer == "" && cfg.hostKubeconfig == "" {
		return runtimeConfig{}, nil, fmt.Errorf("invalid configuration: SOURCE_NAMESPACE and TARGET_NAMESPACE cannot be the same (%q) when running in pull mode on the same cluster", cfg.sourceNamespace)
	}

	return cfg, allowedTargetIDs, nil
}

func loadConfig(kubeconfig string) (*rest.Config, error) {
	if strings.TrimSpace(kubeconfig) == "" {
		cfg, err := rest.InClusterConfig()
		if err == nil {
			return cfg, nil
		}
		return nil, fmt.Errorf("in-cluster config failed and no kubeconfig provided: %w", err)
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func loadHostPullConfig(kubeconfig, hostAPIServer, tokenFile, caFile string) (*rest.Config, error) {
	if strings.TrimSpace(kubeconfig) != "" {
		return loadConfig(kubeconfig)
	}
	if strings.TrimSpace(hostAPIServer) == "" {
		cfg, err := rest.InClusterConfig()
		if err == nil {
			return cfg, nil
		}
		return nil, fmt.Errorf("in-cluster config failed and HOST_API_SERVER is not set: %w", err)
	}
	if strings.TrimSpace(tokenFile) == "" {
		return nil, errors.New("HOST_TOKEN_FILE is required when HOST_KUBECONFIG is not set")
	}

	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read HOST_TOKEN_FILE %q: %w", tokenFile, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, fmt.Errorf("HOST_TOKEN_FILE %q is empty", tokenFile)
	}

	return &rest.Config{
		Host:            hostAPIServer,
		BearerToken:     token,
		BearerTokenFile: tokenFile,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: caFile,
		},
	}, nil
}

func envOrDefault(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func parseBoolEnv(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}

	switch strings.ToLower(raw) {
	case "1", "true", "t", "yes", "y", "on":
		return true, nil
	case "0", "false", "f", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported boolean value %q", raw)
	}
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	return time.ParseDuration(raw)
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

func normalizeDeletePolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "retain":
		return "retain"
	case "delete":
		return "delete"
	default:
		return ""
	}
}

func namespaceOrAll(ns string) string {
	if strings.TrimSpace(ns) == "" {
		return metav1.NamespaceAll
	}
	return ns
}
