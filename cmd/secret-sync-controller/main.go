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
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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

type syncTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name,omitempty"`
}

func (t syncTarget) ID() string {
	if t.Name != "" {
		return fmt.Sprintf("cluster/%s/%s", t.Namespace, t.Name)
	}
	return fmt.Sprintf("cluster/%s", t.Namespace)
}

func (t syncTarget) namespaceID() string {
	return fmt.Sprintf("cluster/%s", t.Namespace)
}

func (t syncTarget) targetName(sourceName string) string {
	if strings.TrimSpace(t.Name) != "" {
		return t.Name
	}
	return sourceName
}

type controller struct {
	hostClient       kubernetes.Interface
	localClient      kubernetes.Interface
	cfg              runtimeConfig
	allowedTargetIDs map[string]struct{}
	startedAt        time.Time
	ready            atomic.Bool
	metrics          metricsState
	bridgeVerifier   *bridgeVerifier
	bridgeHTTPClient *http.Client
}

type pullQueueAction string

const (
	pullActionReconcile pullQueueAction = "reconcile"
	pullActionDelete    pullQueueAction = "delete"
)

type pullQueueItem struct {
	action    pullQueueAction
	namespace string
	name      string
	secret    *corev1.Secret
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
		c.bridgeVerifier, err = newBridgeVerifier(cfg.bridgeTrustIssuers, cfg.bridgeAllowedSubjects)
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

func (c *controller) runPush(ctx context.Context) {
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
			start := time.Now()
			if err := c.reconcile(ctx, sec); err != nil {
				c.metrics.reconcileErrors.Add(1)
				c.recordError("push_reconcile_failed")
				log.Printf("reconcile add %s/%s failed: %v", sec.Namespace, sec.Name, err)
			} else {
				c.recordSuccess(time.Since(start))
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			sec, ok := newObj.(*corev1.Secret)
			if !ok {
				return
			}
			start := time.Now()
			if err := c.reconcile(ctx, sec); err != nil {
				c.metrics.reconcileErrors.Add(1)
				c.recordError("push_reconcile_failed")
				log.Printf("reconcile update %s/%s failed: %v", sec.Namespace, sec.Name, err)
			} else {
				c.recordSuccess(time.Since(start))
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
			start := time.Now()
			if err := c.handleDelete(ctx, sec); err != nil {
				c.metrics.deleteErrors.Add(1)
				c.recordError("push_delete_failed")
				log.Printf("handle delete %s/%s failed: %v", sec.Namespace, sec.Name, err)
			} else {
				c.recordSuccess(time.Since(start))
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

func (c *controller) runPull(ctx context.Context) {
	factory := informers.NewSharedInformerFactoryWithOptions(
		c.hostClient,
		0,
		informers.WithNamespace(c.cfg.sourceNamespace),
	)
	secretInformer := factory.Core().V1().Secrets().Informer()
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pull-secrets")
	defer queue.ShutDown()

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			sec, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			c.enqueuePullReconcile(queue, sec.Namespace, sec.Name)
		},
		UpdateFunc: func(_, newObj interface{}) {
			sec, ok := newObj.(*corev1.Secret)
			if !ok {
				return
			}
			c.enqueuePullReconcile(queue, sec.Namespace, sec.Name)
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
			c.enqueuePullDelete(queue, sec)
		},
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		log.Fatal("cache sync failed")
	}

	for i := 0; i < 2; i++ {
		go c.runPullWorker(ctx, queue, secretInformer.GetIndexer())
	}
	c.ready.Store(true)

	<-ctx.Done()
}

func (c *controller) enqueuePullReconcile(queue workqueue.TypedRateLimitingInterface[interface{}], namespace, name string) {
	queue.Add(pullQueueItem{
		action:    pullActionReconcile,
		namespace: namespace,
		name:      name,
	})
}

func (c *controller) enqueuePullDelete(queue workqueue.TypedRateLimitingInterface[interface{}], src *corev1.Secret) {
	queue.Add(pullQueueItem{
		action:    pullActionDelete,
		namespace: src.Namespace,
		name:      src.Name,
		secret:    src.DeepCopy(),
	})
}

func (c *controller) runPullWorker(ctx context.Context, queue workqueue.TypedRateLimitingInterface[interface{}], indexer cache.Indexer) {
	for c.processNextPullItem(ctx, queue, indexer) {
	}
}

func (c *controller) processNextPullItem(ctx context.Context, queue workqueue.TypedRateLimitingInterface[interface{}], indexer cache.Indexer) bool {
	raw, shutdown := queue.Get()
	if shutdown {
		return false
	}
	defer queue.Done(raw)

	item, ok := raw.(pullQueueItem)
	if !ok {
		queue.Forget(raw)
		log.Printf("ignoring unexpected queue item type %T", raw)
		return true
	}

	var err error
	switch item.action {
	case pullActionReconcile:
		start := time.Now()
		key := fmt.Sprintf("%s/%s", item.namespace, item.name)
		obj, exists, getErr := indexer.GetByKey(key)
		if getErr != nil {
			err = fmt.Errorf("index lookup %s: %w", key, getErr)
			break
		}
		if !exists {
			queue.Forget(raw)
			return true
		}
		sec, castOK := obj.(*corev1.Secret)
		if !castOK {
			queue.Forget(raw)
			log.Printf("ignoring index object for %s with unexpected type %T", key, obj)
			return true
		}
		err = c.reconcilePull(ctx, sec)
		if err != nil {
			c.metrics.reconcileErrors.Add(1)
			c.recordError("pull_reconcile_failed")
			log.Printf("reconcile pull %s failed: %v", key, err)
		} else {
			c.recordSuccess(time.Since(start))
		}
	case pullActionDelete:
		if item.secret != nil {
			start := time.Now()
			err = c.handleDeletePull(ctx, item.secret)
			if err != nil {
				c.metrics.deleteErrors.Add(1)
				c.recordError("pull_delete_failed")
				log.Printf("handle pull delete %s/%s failed: %v", item.namespace, item.name, err)
			} else {
				c.recordSuccess(time.Since(start))
			}
		}
	default:
		queue.Forget(raw)
		log.Printf("ignoring queue item with unknown action %q", item.action)
		return true
	}

	if err == nil {
		queue.Forget(raw)
		return true
	}

	queue.AddRateLimited(raw)
	return true
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

func (c *controller) reconcilePull(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		return nil
	}
	c.metrics.reconcileTotal.Add(1)

	targets, err := c.resolvePullTargets(src)
	if err != nil {
		msg := fmt.Sprintf("invalid pull targets for %s/%s: %v", src.Namespace, src.Name, err)
		c.emitWarningEvent(ctx, src, eventReasonConfigInvalid, msg)
		return errors.New(msg)
	}

	checksum, err := secretChecksum(src)
	if err != nil {
		return fmt.Errorf("compute checksum: %w", err)
	}

	var errs []string
	for _, target := range targets {
		if targetErr := c.validatePullTarget(src, target); targetErr != nil {
			c.emitWarningEvent(ctx, src, eventReasonTargetBlocked, targetErr.Error())
			errs = append(errs, targetErr.Error())
			continue
		}
		if targetErr := c.reconcileIntoNamespace(ctx, c.localClient, src, target.Namespace, target.targetName(src.Name), target.ID(), checksum); targetErr != nil {
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

	return c.reconcileIntoNamespace(ctx, targetClient, src, target.Namespace, target.targetName(src.Name), target.ID(), checksum)
}

func (c *controller) reconcileIntoNamespace(ctx context.Context, targetClient kubernetes.Interface, src *corev1.Secret, targetNamespace, targetName, targetID, checksum string) error {
	expectedSourceRef := fmt.Sprintf("%s/%s", src.Namespace, src.Name)
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
			msg := fmt.Sprintf("target namespace %q not found for %q", targetNamespace, targetID)
			c.emitWarningEvent(ctx, src, eventReasonTargetMissing, msg)
			return errors.New(msg)
		}
		if createErr == nil {
			c.metrics.syncCreatedTotal.Add(1)
			c.emitNormalEvent(ctx, src, eventReasonCreated, fmt.Sprintf("synced secret to %s", targetID))
			c.logReconcileAction("created", src, targetID, targetNamespace, targetName)
		}
		return createErr
	}

	if err := ensureManagedTarget(existing, expectedSourceRef); err != nil {
		msg := fmt.Sprintf("target %q ownership conflict: %v", targetID, err)
		c.emitWarningEvent(ctx, src, eventReasonTargetOwned, msg)
		return errors.New(msg)
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
			c.emitNormalEvent(ctx, src, eventReasonUpdated, fmt.Sprintf("recreated immutable secret in %s", targetID))
			c.logReconcileAction("recreated", src, targetID, targetNamespace, targetName)
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
		c.emitNormalEvent(ctx, src, eventReasonUpdated, fmt.Sprintf("updated synced secret in %s", targetID))
		c.logReconcileAction("updated", src, targetID, targetNamespace, targetName)
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

		targetName := target.targetName(src.Name)
		existing, getErr := targetClient.CoreV1().Secrets(target.Namespace).Get(ctx, targetName, metav1.GetOptions{})
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

		delErr := targetClient.CoreV1().Secrets(target.Namespace).Delete(ctx, targetName, metav1.DeleteOptions{})
		if delErr == nil {
			c.metrics.syncDeletedTotal.Add(1)
			c.logReconcileAction("deleted", src, target.ID(), target.Namespace, targetName)
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

func (c *controller) handleDeletePull(ctx context.Context, src *corev1.Secret) error {
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

	targets, err := c.resolvePullTargets(src)
	if err != nil {
		return nil
	}

	var errs []string
	for _, target := range targets {
		if targetErr := c.validatePullTarget(src, target); targetErr != nil {
			continue
		}

		targetName := target.targetName(src.Name)
		existing, getErr := c.localClient.CoreV1().Secrets(target.Namespace).Get(ctx, targetName, metav1.GetOptions{})
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

		delErr := c.localClient.CoreV1().Secrets(target.Namespace).Delete(ctx, targetName, metav1.DeleteOptions{})
		if delErr == nil {
			c.metrics.syncDeletedTotal.Add(1)
			c.logReconcileAction("deleted", src, target.ID(), target.Namespace, targetName)
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
	if target.Kind != targetKindCluster {
		return fmt.Errorf("target %q is blocked: push mode only allows kind=%s", target.ID(), targetKindCluster)
	}
	if target.Kind == targetKindCluster && target.Namespace == src.Namespace {
		return fmt.Errorf("target %q points to source namespace %q and is not allowed", target.ID(), src.Namespace)
	}

	if c.cfg.pullNamespaceIsolation {
		return fmt.Errorf("target %q is blocked: PULL_NAMESPACE_ISOLATION is only supported in pull mode", target.ID())
	}

	if len(c.allowedTargetIDs) > 0 && !c.isTargetAllowed(target) {
		return fmt.Errorf("target %q is blocked by ALLOWED_SYNC_TARGETS", target.ID())
	}

	return nil
}

func (c *controller) resolvePullTargets(src *corev1.Secret) ([]syncTarget, error) {
	raw := strings.TrimSpace(src.Annotations[annSyncTargets])
	if raw == "" {
		return []syncTarget{{Kind: targetKindCluster, Namespace: c.cfg.targetNamespace}}, nil
	}
	return parseTargets(raw)
}

func (c *controller) validatePullTarget(src *corev1.Secret, target syncTarget) error {
	if target.Kind != targetKindCluster {
		return fmt.Errorf("target %q is blocked: pull mode only allows kind=%s", target.ID(), targetKindCluster)
	}
	if c.cfg.pullNamespaceIsolation {
		if c.cfg.podNamespace == "" {
			return fmt.Errorf("target %q is blocked: PULL_NAMESPACE_ISOLATION requires POD_NAMESPACE", target.ID())
		}
		if target.Namespace != c.cfg.podNamespace {
			return fmt.Errorf("target %q is blocked: PULL_NAMESPACE_ISOLATION only allows namespace %q", target.ID(), c.cfg.podNamespace)
		}
	}
	if c.cfg.hostKubeconfig == "" && c.cfg.hostAPIServer == "" && target.Namespace == src.Namespace {
		return fmt.Errorf("target %q points to source namespace %q and is not allowed in same-cluster pull mode", target.ID(), src.Namespace)
	}
	if len(c.allowedTargetIDs) > 0 && !c.isTargetAllowed(target) {
		return fmt.Errorf("target %q is blocked by ALLOWED_SYNC_TARGETS", target.ID())
	}
	return nil
}

func (c *controller) isTargetAllowed(target syncTarget) bool {
	if _, ok := c.allowedTargetIDs[target.ID()]; ok {
		return true
	}
	if target.Name != "" {
		if _, ok := c.allowedTargetIDs[target.namespaceID()]; ok {
			return true
		}
	}
	return false
}

func (c *controller) targetClient(target syncTarget) (kubernetes.Interface, error) {
	switch target.Kind {
	case targetKindCluster:
		return c.hostClient, nil
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
		t.Name = strings.TrimSpace(t.Name)

		if t.Namespace == "" {
			return nil, fmt.Errorf("target[%d]: namespace is required", i)
		}
		switch t.Kind {
		case targetKindCluster:
		default:
			return nil, fmt.Errorf("target[%d]: unsupported kind %q (only %q is allowed)", i, t.Kind, targetKindCluster)
		}
		if t.Name != "" {
			if errs := validation.IsDNS1123Subdomain(t.Name); len(errs) > 0 {
				return nil, fmt.Errorf("target[%d]: invalid name %q: %s", i, t.Name, strings.Join(errs, ", "))
			}
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

func (c *controller) logReconcileAction(action string, src *corev1.Secret, targetID, targetNamespace, targetName string) {
	if !c.cfg.logReconcileActions {
		return
	}
	log.Printf(
		"reconcile %s source=%s/%s target=%s targetSecret=%s/%s",
		action,
		src.Namespace,
		src.Name,
		targetID,
		targetNamespace,
		targetName,
	)
}

func (c *controller) emitNormalEvent(ctx context.Context, src *corev1.Secret, reason, message string) {
	c.emitEvent(ctx, src, corev1.EventTypeNormal, reason, message)
}

func (c *controller) emitEvent(ctx context.Context, src *corev1.Secret, eventType, reason, message string) {
	if c.cfg.syncMode == modePull && c.cfg.sourceProvider == sourceProviderBridge {
		return
	}

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

func (c *controller) serveHTTP(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.handleHealthz)
	mux.HandleFunc("/readyz", c.handleReadyz)
	mux.HandleFunc("/version", c.handleVersion)
	mux.HandleFunc("/status", c.handleStatus)
	mux.HandleFunc("/metrics", c.handleMetrics)
	mux.HandleFunc("/bridge/v1/secrets", c.handleBridgeList)
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
