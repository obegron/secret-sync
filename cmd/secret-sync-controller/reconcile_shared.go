package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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
			c.logVerbosef("target missing source=%s/%s target=%s: %s", src.Namespace, src.Name, targetID, msg)
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
		c.logVerbosef("ownership conflict source=%s/%s target=%s: %s", src.Namespace, src.Name, targetID, msg)
		c.emitWarningEvent(ctx, src, eventReasonTargetOwned, msg)
		return errors.New(msg)
	}

	if existing.Annotations[annChecksum] == checksum {
		c.logVerbosef("skip update source=%s/%s target=%s targetSecret=%s/%s: checksum unchanged", src.Namespace, src.Name, targetID, targetNamespace, targetName)
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
	managedBy := existing.Annotations[annManagedBy]
	sourceRef := existing.Annotations[annSourceRef]

	if managedBy != controllerName {
		return fmt.Errorf("%s=%q (expected %q)", annManagedBy, managedBy, controllerName)
	}
	if sourceRef != expectedSourceRef {
		return fmt.Errorf("%s=%q (expected %q)", annSourceRef, sourceRef, expectedSourceRef)
	}

	return nil
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
