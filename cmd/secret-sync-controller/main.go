package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"secret-sync-controller/internal/auth"
)

var Version = "dev"

const (
	controllerName = "secret-sync-controller"
	modePush       = "push"
	modePull       = "pull"
	modeSource     = "source"

	sourceProviderKubernetes = "kubernetes"
	sourceProviderBridge     = "bridge"

	labelSyncEnabled = "obegron.github.io/secret-sync-enabled"
	annSyncTargets   = "obegron.github.io/secret-sync-targets"
	annDeletePolicy  = "obegron.github.io/delete-policy"

	annManagedBy = "obegron.github.io/managed-by"
	annSourceRef = "obegron.github.io/source"
	annChecksum  = "obegron.github.io/checksum"

	targetKindCluster = "cluster"

	eventReasonConfigInvalid = "SyncConfigInvalid"
	eventReasonTargetBlocked = "SyncTargetBlocked"
	eventReasonTargetOwned   = "SyncTargetOwnershipConflict"
	eventReasonTargetMissing = "SyncTargetNamespaceMissing"
	eventReasonCreated       = "SyncCreated"
	eventReasonUpdated       = "SyncUpdated"
)

type controller struct {
	hostClient       kubernetes.Interface
	localClient      kubernetes.Interface
	cfg              runtimeConfig
	allowedTargetIDs map[string]struct{}
	startedAt        time.Time
	ready            atomic.Bool
	metrics          metricsState
	bridgeVerifier   *auth.Verifier
	bridgeHTTPClient *http.Client
}

func main() {
	log.Printf("starting %s version %s", controllerName, Version)

	cfg, allowedTargetIDs, err := loadRuntimeConfig()
	if err != nil {
		log.Fatal(err)
	}

	var hostRest *rest.Config
	switch {
	case cfg.syncMode == modePull && cfg.sourceProvider == sourceProviderKubernetes:
		hostRest, err = loadHostPullConfig(cfg.hostKubeconfig, cfg.hostAPIServer, cfg.hostTokenFile, cfg.hostCAFile)
	default:
		hostRest, err = loadConfig(cfg.hostKubeconfig)
	}
	if err != nil {
		log.Fatalf("load host config: %v", err)
	}

	hostClient, err := kubernetes.NewForConfig(hostRest)
	if err != nil {
		log.Fatalf("build host client: %v", err)
	}
	var localClient kubernetes.Interface
	if cfg.syncMode != modeSource {
		localRest, localErr := rest.InClusterConfig()
		if localErr != nil {
			log.Fatalf("build local in-cluster config: %v", localErr)
		}
		localClient, err = kubernetes.NewForConfig(localRest)
		if err != nil {
			log.Fatalf("build local client: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := &controller{
		hostClient:       hostClient,
		localClient:      localClient,
		cfg:              cfg,
		allowedTargetIDs: allowedTargetIDs,
		startedAt:        time.Now(),
	}
	if cfg.syncMode == modeSource && len(cfg.bridgeTrustIssuers) > 0 {
		c.bridgeVerifier, err = auth.NewVerifier(cfg.bridgeTrustIssuers, cfg.bridgeAllowedSubjects)
		if err != nil {
			log.Fatalf("build bridge verifier: %v", err)
		}
	}
	if cfg.syncMode == modePull && cfg.sourceProvider == sourceProviderBridge {
		c.bridgeHTTPClient, err = newBridgeHTTPClient(cfg.bridgeCAFile, cfg.bridgeTokenFile)
		if err != nil {
			log.Fatalf("build bridge client: %v", err)
		}
	}
	go c.serveHTTP(ctx)
	c.run(ctx)
}

func (c *controller) run(ctx context.Context) {
	if c.cfg.syncMode == modeSource {
		c.runSource(ctx)
		return
	}
	if c.cfg.syncMode == modePull {
		if c.cfg.sourceProvider == sourceProviderBridge {
			c.runPullBridge(ctx)
			return
		}
		c.runPull(ctx)
		return
	}
	c.runPush(ctx)
}

func (c *controller) runSource(ctx context.Context) {
	c.ready.Store(true)
	<-ctx.Done()
}

func (c *controller) serveHTTP(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.handleHealthz)
	mux.HandleFunc("/readyz", c.handleReadyz)
	mux.HandleFunc("/version", c.handleVersion)
	mux.HandleFunc("/status", c.handleStatus)
	mux.HandleFunc("/metrics", c.handleMetrics)
	mux.HandleFunc("/bridge/v1/secrets", c.handleBridgeList)
	mux.HandleFunc("/vcluster/v1/kubeconfig", c.handleVClusterKubeconfig)
	mux.HandleFunc("/.well-known/openid-configuration", c.handleOIDCConfigProxy)
	mux.HandleFunc("/openid/v1/jwks", c.handleJWKSProxy)

	server := &http.Server{
		Addr:    c.cfg.metricsBindAddress,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()

	log.Printf("metrics server listening on %s", c.cfg.metricsBindAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("metrics server failed: %v", err)
	}
}
