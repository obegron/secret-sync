package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
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
