package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var Version = "dev"

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type config struct {
	Mode               string
	EnvironmentBaseURL string
	Port               string

	// proxy mode inputs
	KubernetesAPIServer string
	TokenPath           string
	CAPath              string

	// static mode inputs
	StaticOIDCConfigFile string
	StaticJWKSFile       string
	StaticOIDCConfigJSON string
	StaticJWKSJSON       string
}

type app struct {
	cfg            config
	k8sClient      *http.Client
	staticOIDCJSON []byte
	staticJWKSJSON []byte
}

func main() {
	cfg := config{
		Mode:                 strings.ToLower(strings.TrimSpace(envOrDefault("OIDC_MODE", "proxy"))),
		EnvironmentBaseURL:   strings.TrimSpace(os.Getenv("ENVIRONMENT_BASE_URL")),
		Port:                 envOrDefault("PORT", "8080"),
		KubernetesAPIServer:  strings.TrimSpace(os.Getenv("KUBERNETES_API_SERVER")),
		TokenPath:            envOrDefault("K8S_SA_TOKEN_PATH", serviceAccountTokenPath),
		CAPath:               envOrDefault("K8S_SA_CA_PATH", serviceAccountCAPath),
		StaticOIDCConfigFile: strings.TrimSpace(os.Getenv("STATIC_OIDC_CONFIG_FILE")),
		StaticJWKSFile:       strings.TrimSpace(os.Getenv("STATIC_JWKS_FILE")),
		StaticOIDCConfigJSON: strings.TrimSpace(os.Getenv("STATIC_OIDC_CONFIG_JSON")),
		StaticJWKSJSON:       strings.TrimSpace(os.Getenv("STATIC_JWKS_JSON")),
	}

	if cfg.Mode != "proxy" && cfg.Mode != "static" {
		log.Fatalf("invalid OIDC_MODE %q (expected proxy or static)", cfg.Mode)
	}
	if cfg.EnvironmentBaseURL == "" {
		log.Fatal("ENVIRONMENT_BASE_URL must be set")
	}

	a := &app{cfg: cfg}
	if err := a.init(); err != nil {
		log.Fatalf("initialize app: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/", a.handleRoot)
	mux.HandleFunc("/.well-known/openid-configuration", a.handleOIDCConfig)
	mux.HandleFunc("/openid/v1/jwks", a.handleJWKS)
	mux.HandleFunc("/version", a.handleVersion)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("starting oidc-helper version %s mode=%s on :%s", Version, cfg.Mode, cfg.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func (a *app) init() error {
	if a.cfg.Mode == "static" {
		oidcJSON, err := loadStaticJSON(a.cfg.StaticOIDCConfigFile, a.cfg.StaticOIDCConfigJSON, "STATIC_OIDC_CONFIG")
		if err != nil {
			return err
		}
		jwksJSON, err := loadStaticJSON(a.cfg.StaticJWKSFile, a.cfg.StaticJWKSJSON, "STATIC_JWKS")
		if err != nil {
			return err
		}
		if !json.Valid(oidcJSON) {
			return errors.New("STATIC_OIDC_CONFIG is not valid JSON")
		}
		if !json.Valid(jwksJSON) {
			return errors.New("STATIC_JWKS is not valid JSON")
		}
		a.staticOIDCJSON = oidcJSON
		a.staticJWKSJSON = jwksJSON
		return nil
	}

	tokenBytes, err := os.ReadFile(a.cfg.TokenPath)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	caBytes, err := os.ReadFile(a.cfg.CAPath)
	if err != nil {
		return fmt.Errorf("read ca: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return errors.New("append CA cert failed")
	}

	if a.cfg.KubernetesAPIServer == "" {
		host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
		port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
		if host == "" || port == "" {
			return errors.New("KUBERNETES_API_SERVER or KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT must be set")
		}
		a.cfg.KubernetesAPIServer = "https://" + host + ":" + port
	}

	a.k8sClient = &http.Client{
		Transport: &bearerAuthTransport{
			token: strings.TrimSpace(string(tokenBytes)),
			transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: caPool},
			},
		},
		Timeout: 10 * time.Second,
	}

	return nil
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"msg": "OK"})
}

func (a *app) handleVersion(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(Version + "\n"))
}

func (a *app) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/health", http.StatusFound)
}

func (a *app) handleOIDCConfig(w http.ResponseWriter, _ *http.Request) {
	if a.cfg.Mode == "static" {
		var oidcData map[string]interface{}
		if err := json.Unmarshal(a.staticOIDCJSON, &oidcData); err != nil {
			httpErrorJSON(w, http.StatusInternalServerError, fmt.Sprintf("error parsing static OIDC configuration: %v", err))
			return
		}
		oidcData["jwks_uri"] = strings.TrimSuffix(a.cfg.EnvironmentBaseURL, "/") + "/openid/v1/jwks"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcData)
		return
	}

	body, err := a.fetchFromK8s("/.well-known/openid-configuration")
	if err != nil {
		httpErrorJSON(w, http.StatusFailedDependency, fmt.Sprintf("error getting OIDC configuration: %v", err))
		return
	}

	var oidcData map[string]interface{}
	if err := json.Unmarshal(body, &oidcData); err != nil {
		httpErrorJSON(w, http.StatusInternalServerError, fmt.Sprintf("error parsing OIDC configuration: %v", err))
		return
	}
	oidcData["jwks_uri"] = strings.TrimSuffix(a.cfg.EnvironmentBaseURL, "/") + "/openid/v1/jwks"

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(oidcData)
}

func (a *app) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	if a.cfg.Mode == "static" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(a.staticJWKSJSON)
		return
	}

	body, err := a.fetchFromK8s("/openid/v1/jwks")
	if err != nil {
		httpErrorJSON(w, http.StatusFailedDependency, fmt.Sprintf("error getting JWKS: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (a *app) fetchFromK8s(path string) ([]byte, error) {
	resp, err := a.k8sClient.Get(strings.TrimSuffix(a.cfg.KubernetesAPIServer, "/") + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubernetes API returned status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func loadStaticJSON(filePath, rawJSON, name string) ([]byte, error) {
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read %s file %q: %w", name, filePath, err)
		}
		return b, nil
	}
	if rawJSON != "" {
		return []byte(rawJSON), nil
	}
	return nil, fmt.Errorf("%s is required in static mode (file or inline JSON)", name)
}

func httpErrorJSON(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"msg": msg})
}

func envOrDefault(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

type bearerAuthTransport struct {
	token     string
	transport http.RoundTripper
}

func (t *bearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}
