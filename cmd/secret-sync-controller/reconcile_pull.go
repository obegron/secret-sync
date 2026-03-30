package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *controller) reconcilePull(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		c.logVerbosef("skip pull reconcile source=%s/%s: %s is %q", src.Namespace, src.Name, labelSyncEnabled, src.Labels[labelSyncEnabled])
		return nil
	}
	c.metrics.reconcileTotal.Add(1)

	targets, err := c.resolvePullTargets(src)
	if err != nil {
		msg := fmt.Sprintf("invalid pull targets for %s/%s: %v", src.Namespace, src.Name, err)
		c.logVerbosef("reject pull reconcile source=%s/%s: %s", src.Namespace, src.Name, msg)
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
			c.logVerbosef("block pull target source=%s/%s target=%s: %v", src.Namespace, src.Name, target.ID(), targetErr)
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

func (c *controller) handleDeletePull(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		c.logVerbosef("skip pull delete source=%s/%s: %s is %q", src.Namespace, src.Name, labelSyncEnabled, src.Labels[labelSyncEnabled])
		return nil
	}
	c.metrics.deleteTotal.Add(1)

	rawDeletePolicy := src.Annotations[annDeletePolicy]
	deletePolicy := normalizeDeletePolicy(rawDeletePolicy)
	if strings.TrimSpace(rawDeletePolicy) != "" && deletePolicy == "" {
		c.logVerbosef("invalid pull delete policy source=%s/%s: %q, falling back to default %q", src.Namespace, src.Name, rawDeletePolicy, c.cfg.defaultDeletePolicy)
	}
	if deletePolicy == "" {
		deletePolicy = c.cfg.defaultDeletePolicy
	}
	if deletePolicy == "retain" {
		c.logVerbosef("retain pull delete source=%s/%s due to delete policy %q", src.Namespace, src.Name, deletePolicy)
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
			c.logVerbosef("ownership conflict on pull delete source=%s/%s target=%s: %s", src.Namespace, src.Name, target.ID(), msg)
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
