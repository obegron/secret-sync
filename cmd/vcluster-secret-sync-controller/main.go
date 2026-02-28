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
	controllerName = "vcluster-secret-sync-controller"

	// Source selector and contract.
	labelSyncEnabled = "obegron.github.io/sync-to-vcluster"

	annVclusterName      = "obegron.github.io/vcluster-name"
	annVclusterNamespace = "obegron.github.io/vcluster-namespace"
	annDeletePolicy      = "obegron.github.io/delete-policy"

	annManagedBy = "obegron.github.io/managed-by"
	annSourceRef = "obegron.github.io/source"
	annChecksum  = "obegron.github.io/checksum"

	eventReasonConfigInvalid = "SyncConfigInvalid"
	eventReasonTargetMissing = "SyncTargetNamespaceMissing"
	eventReasonCreated       = "SyncCreated"
	eventReasonUpdated       = "SyncUpdated"
)

type runtimeConfig struct {
	hostKubeconfig        string
	sourceNamespace       string
	vclusterKubeconfigDir string
	defaultDeletePolicy   string
	metricsBindAddress    string
}

type controller struct {
	hostClient kubernetes.Interface
	cfg        runtimeConfig
	ready      atomic.Bool
	metrics    metricsState
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
	cfg := runtimeConfig{
		hostKubeconfig:        os.Getenv("HOST_KUBECONFIG"),
		sourceNamespace:       os.Getenv("SOURCE_NAMESPACE"),
		vclusterKubeconfigDir: envOrDefault("VCLUSTER_KUBECONFIG_DIR", "/etc/vcluster-kubeconfigs"),
		defaultDeletePolicy:   normalizeDeletePolicy(envOrDefault("DEFAULT_DELETE_POLICY", "delete")),
		metricsBindAddress:    envOrDefault("METRICS_BIND_ADDRESS", ":8080"),
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

	c := &controller{hostClient: hostClient, cfg: cfg}
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

	vclusterName := strings.TrimSpace(src.Annotations[annVclusterName])
	targetNamespace := strings.TrimSpace(src.Annotations[annVclusterNamespace])
	if vclusterName == "" || targetNamespace == "" {
		msg := fmt.Sprintf("missing required annotations %s and/or %s", annVclusterName, annVclusterNamespace)
		c.emitWarningEvent(ctx, src, eventReasonConfigInvalid, msg)
		return errors.New(msg)
	}

	targetClient, err := c.vclusterClient(vclusterName)
	if err != nil {
		return fmt.Errorf("build vcluster client for %q: %w", vclusterName, err)
	}

	checksum, err := secretChecksum(src)
	if err != nil {
		return fmt.Errorf("compute checksum: %w", err)
	}

	targetName := src.Name
	existing, err := targetClient.CoreV1().Secrets(targetNamespace).Get(ctx, targetName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get target secret: %w", err)
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetName,
			Namespace: targetNamespace,
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
		_, createErr := targetClient.CoreV1().Secrets(targetNamespace).Create(ctx, desired, metav1.CreateOptions{})
		if apierrors.IsNotFound(createErr) {
			msg := fmt.Sprintf("target namespace %q not found in vcluster %q", targetNamespace, vclusterName)
			c.emitWarningEvent(ctx, src, eventReasonTargetMissing, msg)
			return errors.New(msg)
		}
		if createErr == nil {
			c.metrics.syncCreatedTotal.Add(1)
			c.emitNormalEvent(ctx, src, eventReasonCreated, fmt.Sprintf("synced secret to %s/%s in vcluster %s", targetNamespace, targetName, vclusterName))
		}
		return createErr
	}

	if existing.Annotations[annChecksum] == checksum {
		return nil
	}

	if existing.Immutable != nil && *existing.Immutable {
		if delErr := targetClient.CoreV1().Secrets(targetNamespace).Delete(ctx, targetName, metav1.DeleteOptions{}); delErr != nil {
			return fmt.Errorf("delete immutable secret before recreate: %w", delErr)
		}
		_, createErr := targetClient.CoreV1().Secrets(targetNamespace).Create(ctx, desired, metav1.CreateOptions{})
		if createErr == nil {
			c.metrics.syncRecreatedTotal.Add(1)
			c.emitNormalEvent(ctx, src, eventReasonUpdated, fmt.Sprintf("recreated immutable secret in %s/%s in vcluster %s", targetNamespace, targetName, vclusterName))
		}
		return createErr
	}

	existing.Type = desired.Type
	existing.Data = desired.Data
	existing.Immutable = desired.Immutable
	existing.Annotations = desired.Annotations
	_, updateErr := targetClient.CoreV1().Secrets(targetNamespace).Update(ctx, existing, metav1.UpdateOptions{})
	if updateErr == nil {
		c.metrics.syncUpdatedTotal.Add(1)
		c.emitNormalEvent(ctx, src, eventReasonUpdated, fmt.Sprintf("updated synced secret in %s/%s in vcluster %s", targetNamespace, targetName, vclusterName))
	}
	return updateErr
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

func (c *controller) handleDelete(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		return nil
	}

	deletePolicy := normalizeDeletePolicy(src.Annotations[annDeletePolicy])
	if deletePolicy == "" {
		deletePolicy = c.cfg.defaultDeletePolicy
	}
	if deletePolicy == "retain" {
		return nil
	}

	vclusterName := strings.TrimSpace(src.Annotations[annVclusterName])
	targetNamespace := strings.TrimSpace(src.Annotations[annVclusterNamespace])
	if vclusterName == "" || targetNamespace == "" {
		return nil
	}

	targetClient, err := c.vclusterClient(vclusterName)
	if err != nil {
		return fmt.Errorf("build vcluster client for %q: %w", vclusterName, err)
	}

	err = targetClient.CoreV1().Secrets(targetNamespace).Delete(ctx, src.Name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err == nil {
		c.metrics.deleteTotal.Add(1)
		c.metrics.syncDeletedTotal.Add(1)
	}
	return err
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

func (c *controller) vclusterClient(vclusterName string) (kubernetes.Interface, error) {
	kubeconfig := filepath.Join(c.cfg.vclusterKubeconfigDir, fmt.Sprintf("%s.kubeconfig", vclusterName))
	restCfg, err := loadConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(restCfg)
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
