package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	controllerName = "secret-sync-controller"

	labelSyncEnabled = "obegron.github.io/secret-sync-enabled"
	annSyncTargets   = "obegron.github.io/secret-sync-targets"
	annDeletePolicy  = "obegron.github.io/delete-policy"

	annManagedBy = "obegron.github.io/managed-by"
	annSourceRef = "obegron.github.io/source"
	annChecksum  = "obegron.github.io/checksum"

	targetKindCluster  = "cluster"
	targetKindVcluster = "vcluster"

	eventReasonConfigInvalid = "SyncConfigInvalid"
	eventReasonTargetInvalid = "SyncTargetInvalid"
	eventReasonTargetBlocked = "SyncTargetBlocked"
	eventReasonTargetOwned   = "SyncTargetOwnershipConflict"
	eventReasonTargetMissing = "SyncTargetNamespaceMissing"
	eventReasonCreated       = "SyncCreated"
	eventReasonUpdated       = "SyncUpdated"
)

type runtimeConfig struct {
	hostKubeconfig        string
	podNamespace          string
	sourceNamespace       string
	vclusterKubeconfigDir string
	defaultDeletePolicy   string
	metricsBindAddress    string
	tenantSafeMode        bool
}

type syncTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Vcluster  string `json:"vcluster,omitempty"`
}

func (t syncTarget) ID() string {
	if t.Kind == targetKindVcluster {
		return fmt.Sprintf("vcluster/%s/%s", t.Vcluster, t.Namespace)
	}
	return fmt.Sprintf("cluster/%s", t.Namespace)
}

type controller struct {
	hostClient       kubernetes.Interface
	cfg              runtimeConfig
	allowedTargetIDs map[string]struct{}
	mu               sync.RWMutex
	vclusterClients  map[string]kubernetes.Interface
	ready            atomic.Bool
	metrics          metricsState
}

type metricsState struct {
	reconcileTotal     atomic.Uint64
	reconcileErrors    atomic.Uint64
	deleteTotal        atomic.Uint64
	deleteErrors       atomic.Uint64
	syncCreatedTotal   atomic.Uint64
	syncUpdatedTotal   atomic.Uint64
	syncRecreatedTotal atomic.Uint64
	syncDeletedTotal   atomic.Uint64
	eventNormalTotal   atomic.Uint64
	eventWarningTotal  atomic.Uint64
	eventErrorTotal    atomic.Uint64
}

func main() {
	tenantSafeMode, err := parseBoolEnv("TENANT_SAFE_MODE", false)
	if err != nil {
		log.Fatalf("invalid TENANT_SAFE_MODE: %v", err)
	}

	podNamespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	sourceNamespace := strings.TrimSpace(os.Getenv("SOURCE_NAMESPACE"))
	if sourceNamespace == "" && tenantSafeMode {
		sourceNamespace = podNamespace
	}

	if tenantSafeMode && sourceNamespace == "" {
		log.Fatal("TENANT_SAFE_MODE requires SOURCE_NAMESPACE (or POD_NAMESPACE)")
	}
	if tenantSafeMode && podNamespace != "" && sourceNamespace != podNamespace {
		log.Fatalf("TENANT_SAFE_MODE requires SOURCE_NAMESPACE (%q) to match POD_NAMESPACE (%q)", sourceNamespace, podNamespace)
	}

	allowedTargetIDs, err := parseAllowedTargetIDs(os.Getenv("ALLOWED_SYNC_TARGETS"))
	if err != nil {
		log.Fatalf("invalid ALLOWED_SYNC_TARGETS: %v", err)
	}

	cfg := runtimeConfig{
		hostKubeconfig:        os.Getenv("HOST_KUBECONFIG"),
		podNamespace:          podNamespace,
		sourceNamespace:       sourceNamespace,
		vclusterKubeconfigDir: envOrDefault("VCLUSTER_KUBECONFIG_DIR", "/etc/vcluster-kubeconfigs"),
		defaultDeletePolicy:   normalizeDeletePolicy(envOrDefault("DEFAULT_DELETE_POLICY", "delete")),
		metricsBindAddress:    envOrDefault("METRICS_BIND_ADDRESS", ":8080"),
		tenantSafeMode:        tenantSafeMode,
	}

	hostRest, err := loadConfig(cfg.hostKubeconfig)
	if err != nil {
		log.Fatalf("load host kubeconfig: %v", err)
	}

	hostClient, err := kubernetes.NewForConfig(hostRest)
	if err != nil {
		log.Fatalf("build host client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := &controller{
		hostClient:       hostClient,
		cfg:              cfg,
		allowedTargetIDs: allowedTargetIDs,
		vclusterClients:  map[string]kubernetes.Interface{},
	}
	go c.serveHTTP(ctx)
	c.run(ctx)
}

func (c *controller) run(ctx context.Context) {
	factory := informers.NewSharedInformerFactoryWithOptions(
		c.hostClient,
		0,
		informers.WithNamespace(namespaceOrAll(c.cfg.sourceNamespace)),
	)
	secretInformer := factory.Core().V1().Secrets().Informer()

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			if err := c.reconcile(ctx, sec); err != nil {
				c.metrics.reconcileErrors.Add(1)
				log.Printf("reconcile add %s/%s failed: %v", sec.Namespace, sec.Name, err)
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			sec, ok := newObj.(*corev1.Secret)
			if !ok {
				return
			}
			if err := c.reconcile(ctx, sec); err != nil {
				c.metrics.reconcileErrors.Add(1)
				log.Printf("reconcile update %s/%s failed: %v", sec.Namespace, sec.Name, err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				sec, ok = tombstone.Obj.(*corev1.Secret)
				if !ok {
					return
				}
			}
			if err := c.handleDelete(ctx, sec); err != nil {
				c.metrics.deleteErrors.Add(1)
				log.Printf("handle delete %s/%s failed: %v", sec.Namespace, sec.Name, err)
			}
		},
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		log.Fatal("cache sync failed")
	}
	c.ready.Store(true)

	<-ctx.Done()
}

func (c *controller) reconcile(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		return nil
	}
	c.metrics.reconcileTotal.Add(1)

	targets, err := parseTargets(src.Annotations[annSyncTargets])
	if err != nil {
		msg := fmt.Sprintf("invalid %s annotation: %v", annSyncTargets, err)
		c.emitWarningEvent(ctx, src, eventReasonConfigInvalid, msg)
		return errors.New(msg)
	}

	checksum, err := secretChecksum(src)
	if err != nil {
		return fmt.Errorf("compute checksum: %w", err)
	}

	var errs []string
	for _, target := range targets {
		if targetErr := c.validateTargetForSource(src, target); targetErr != nil {
			c.emitWarningEvent(ctx, src, eventReasonTargetBlocked, targetErr.Error())
			errs = append(errs, targetErr.Error())
			continue
		}

		if targetErr := c.reconcileTarget(ctx, src, target, checksum); targetErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", target.ID(), targetErr))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

func (c *controller) reconcileTarget(ctx context.Context, src *corev1.Secret, target syncTarget, checksum string) error {
	targetClient, err := c.targetClient(target)
	if err != nil {
		return err
	}

	expectedSourceRef := fmt.Sprintf("%s/%s", src.Namespace, src.Name)
	targetName := src.Name
	existing, err := targetClient.CoreV1().Secrets(target.Namespace).Get(ctx, targetName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get target secret: %w", err)
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetName,
			Namespace: target.Namespace,
			Annotations: map[string]string{
				annManagedBy: controllerName,
				annSourceRef: fmt.Sprintf("%s/%s", src.Namespace, src.Name),
				annChecksum:  checksum,
			},
		},
		Type:      src.Type,
		Data:      src.Data,
		Immutable: src.Immutable,
	}

	if apierrors.IsNotFound(err) {
		_, createErr := targetClient.CoreV1().Secrets(target.Namespace).Create(ctx, desired, metav1.CreateOptions{})
		if apierrors.IsNotFound(createErr) {
			msg := fmt.Sprintf("target namespace %q not found for %q", target.Namespace, target.ID())
			c.emitWarningEvent(ctx, src, eventReasonTargetMissing, msg)
			return errors.New(msg)
		}
		if createErr == nil {
			c.metrics.syncCreatedTotal.Add(1)
			c.emitNormalEvent(ctx, src, eventReasonCreated, fmt.Sprintf("synced secret to %s", target.ID()))
		}
		return createErr
	}

	if err := ensureManagedTarget(existing, expectedSourceRef); err != nil {
		msg := fmt.Sprintf("target %q ownership conflict: %v", target.ID(), err)
		c.emitWarningEvent(ctx, src, eventReasonTargetOwned, msg)
		return errors.New(msg)
	}

	if existing.Annotations[annChecksum] == checksum {
		return nil
	}

	if existing.Immutable != nil && *existing.Immutable {
		if delErr := targetClient.CoreV1().Secrets(target.Namespace).Delete(ctx, targetName, metav1.DeleteOptions{}); delErr != nil {
			return fmt.Errorf("delete immutable secret before recreate: %w", delErr)
		}
		_, createErr := targetClient.CoreV1().Secrets(target.Namespace).Create(ctx, desired, metav1.CreateOptions{})
		if createErr == nil {
			c.metrics.syncRecreatedTotal.Add(1)
			c.emitNormalEvent(ctx, src, eventReasonUpdated, fmt.Sprintf("recreated immutable secret in %s", target.ID()))
		}
		return createErr
	}

	existing.Type = desired.Type
	existing.Data = desired.Data
	existing.Immutable = desired.Immutable
	existing.Annotations = desired.Annotations
	_, updateErr := targetClient.CoreV1().Secrets(target.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	if updateErr == nil {
		c.metrics.syncUpdatedTotal.Add(1)
		c.emitNormalEvent(ctx, src, eventReasonUpdated, fmt.Sprintf("updated synced secret in %s", target.ID()))
	}
	return updateErr
}

func (c *controller) handleDelete(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		return nil
	}
	c.metrics.deleteTotal.Add(1)

	deletePolicy := normalizeDeletePolicy(src.Annotations[annDeletePolicy])
	if deletePolicy == "" {
		deletePolicy = c.cfg.defaultDeletePolicy
	}
	if deletePolicy == "retain" {
		return nil
	}

	targets, err := parseTargets(src.Annotations[annSyncTargets])
	if err != nil {
		return nil
	}

	var errs []string
	for _, target := range targets {
		if targetErr := c.validateTargetForSource(src, target); targetErr != nil {
			continue
		}

		targetClient, targetErr := c.targetClient(target)
		if targetErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", target.ID(), targetErr))
			continue
		}

		existing, getErr := targetClient.CoreV1().Secrets(target.Namespace).Get(ctx, src.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			continue
		}
		if getErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", target.ID(), getErr))
			continue
		}

		expectedSourceRef := fmt.Sprintf("%s/%s", src.Namespace, src.Name)
		if err := ensureManagedTarget(existing, expectedSourceRef); err != nil {
			msg := fmt.Sprintf("target %q ownership conflict: %v", target.ID(), err)
			c.emitWarningEvent(ctx, src, eventReasonTargetOwned, msg)
			errs = append(errs, msg)
			continue
		}

		delErr := targetClient.CoreV1().Secrets(target.Namespace).Delete(ctx, src.Name, metav1.DeleteOptions{})
		if delErr == nil {
			c.metrics.syncDeletedTotal.Add(1)
			continue
		}
		if !apierrors.IsNotFound(delErr) {
			errs = append(errs, fmt.Sprintf("%s: %v", target.ID(), delErr))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

func (c *controller) validateTargetForSource(src *corev1.Secret, target syncTarget) error {
	if target.Kind == targetKindCluster && target.Namespace == src.Namespace {
		return fmt.Errorf("target %q points to source namespace %q and is not allowed", target.ID(), src.Namespace)
	}

	if c.cfg.tenantSafeMode {
		if target.Kind != targetKindVcluster {
			return fmt.Errorf("target %q is blocked: TENANT_SAFE_MODE only allows kind=%s", target.ID(), targetKindVcluster)
		}
		if target.Namespace != c.cfg.sourceNamespace {
			return fmt.Errorf("target %q is blocked: TENANT_SAFE_MODE requires target namespace %q", target.ID(), c.cfg.sourceNamespace)
		}
	}

	if len(c.allowedTargetIDs) > 0 {
		if _, ok := c.allowedTargetIDs[target.ID()]; !ok {
			return fmt.Errorf("target %q is blocked by ALLOWED_SYNC_TARGETS", target.ID())
		}
	}

	return nil
}

func (c *controller) targetClient(target syncTarget) (kubernetes.Interface, error) {
	switch target.Kind {
	case targetKindCluster:
		return c.hostClient, nil
	case targetKindVcluster:
		return c.vclusterClient(target.Vcluster)
	default:
		return nil, fmt.Errorf("unsupported target kind %q", target.Kind)
	}
}

func ensureManagedTarget(existing *corev1.Secret, expectedSourceRef string) error {
	managedBy := strings.TrimSpace(existing.Annotations[annManagedBy])
	sourceRef := strings.TrimSpace(existing.Annotations[annSourceRef])

	if managedBy != controllerName {
		return fmt.Errorf("%s=%q (expected %q)", annManagedBy, managedBy, controllerName)
	}
	if sourceRef != expectedSourceRef {
		return fmt.Errorf("%s=%q (expected %q)", annSourceRef, sourceRef, expectedSourceRef)
	}

	return nil
}

func parseTargets(raw string) ([]syncTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("annotation is required and must be a JSON array")
	}

	var targets []syncTarget
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if len(targets) == 0 {
		return nil, errors.New("at least one target is required")
	}

	seen := map[string]struct{}{}
	result := make([]syncTarget, 0, len(targets))

	for i, t := range targets {
		t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
		t.Namespace = strings.TrimSpace(t.Namespace)
		t.Vcluster = strings.TrimSpace(t.Vcluster)

		if t.Namespace == "" {
			return nil, fmt.Errorf("target[%d]: namespace is required", i)
		}
		switch t.Kind {
		case targetKindCluster:
			if t.Vcluster != "" {
				return nil, fmt.Errorf("target[%d]: vcluster must be empty for kind=cluster", i)
			}
		case targetKindVcluster:
			if t.Vcluster == "" {
				return nil, fmt.Errorf("target[%d]: vcluster is required for kind=vcluster", i)
			}
		default:
			return nil, fmt.Errorf("target[%d]: unsupported kind %q", i, t.Kind)
		}

		if _, ok := seen[t.ID()]; ok {
			continue
		}
		seen[t.ID()] = struct{}{}
		result = append(result, t)
	}

	return result, nil
}

func parseAllowedTargetIDs(raw string) (map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	targets, err := parseTargets(raw)
	if err != nil {
		return nil, err
	}

	result := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		result[target.ID()] = struct{}{}
	}
	return result, nil
}

func (c *controller) emitWarningEvent(ctx context.Context, src *corev1.Secret, reason, message string) {
	c.emitEvent(ctx, src, corev1.EventTypeWarning, reason, message)
}

func (c *controller) emitNormalEvent(ctx context.Context, src *corev1.Secret, reason, message string) {
	c.emitEvent(ctx, src, corev1.EventTypeNormal, reason, message)
}

func (c *controller) emitEvent(ctx context.Context, src *corev1.Secret, eventType, reason, message string) {
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", src.Name),
			Namespace:    src.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "Secret",
			Namespace:  src.Namespace,
			Name:       src.Name,
			UID:        src.UID,
			APIVersion: "v1",
		},
		Reason:  reason,
		Message: message,
		Type:    eventType,
		Source: corev1.EventSource{
			Component: controllerName,
		},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
		Count:          1,
	}

	if _, err := c.hostClient.CoreV1().Events(src.Namespace).Create(ctx, event, metav1.CreateOptions{}); err != nil {
		c.metrics.eventErrorTotal.Add(1)
		log.Printf("emit event %s/%s failed: %v", src.Namespace, src.Name, err)
		return
	}

	if eventType == corev1.EventTypeWarning {
		c.metrics.eventWarningTotal.Add(1)
	} else {
		c.metrics.eventNormalTotal.Add(1)
	}
}

func (c *controller) vclusterClient(vclusterName string) (kubernetes.Interface, error) {
	c.mu.RLock()
	cached, ok := c.vclusterClients[vclusterName]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	kubeconfig := filepath.Join(c.cfg.vclusterKubeconfigDir, fmt.Sprintf("%s.kubeconfig", vclusterName))
	restCfg, err := loadConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if cached, ok := c.vclusterClients[vclusterName]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.vclusterClients[vclusterName] = client
	c.mu.Unlock()

	return client, nil
}

func (c *controller) serveHTTP(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.handleHealthz)
	mux.HandleFunc("/readyz", c.handleReadyz)
	mux.HandleFunc("/metrics", c.handleMetrics)

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

func (c *controller) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (c *controller) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !c.ready.Load() {
		http.Error(w, "not ready\n", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (c *controller) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "secret_sync_reconcile_total %d\n", c.metrics.reconcileTotal.Load())
	fmt.Fprintf(w, "secret_sync_reconcile_errors_total %d\n", c.metrics.reconcileErrors.Load())
	fmt.Fprintf(w, "secret_sync_delete_total %d\n", c.metrics.deleteTotal.Load())
	fmt.Fprintf(w, "secret_sync_delete_errors_total %d\n", c.metrics.deleteErrors.Load())
	fmt.Fprintf(w, "secret_sync_created_total %d\n", c.metrics.syncCreatedTotal.Load())
	fmt.Fprintf(w, "secret_sync_updated_total %d\n", c.metrics.syncUpdatedTotal.Load())
	fmt.Fprintf(w, "secret_sync_recreated_total %d\n", c.metrics.syncRecreatedTotal.Load())
	fmt.Fprintf(w, "secret_sync_deleted_total %d\n", c.metrics.syncDeletedTotal.Load())
	fmt.Fprintf(w, "secret_sync_event_normal_total %d\n", c.metrics.eventNormalTotal.Load())
	fmt.Fprintf(w, "secret_sync_event_warning_total %d\n", c.metrics.eventWarningTotal.Load())
	fmt.Fprintf(w, "secret_sync_event_error_total %d\n", c.metrics.eventErrorTotal.Load())
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

func secretChecksum(secret *corev1.Secret) (string, error) {
	payload := struct {
		Type      corev1.SecretType `json:"type"`
		Data      map[string][]byte `json:"data"`
		Immutable *bool             `json:"immutable,omitempty"`
	}{
		Type:      secret.Type,
		Data:      secret.Data,
		Immutable: secret.Immutable,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
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
