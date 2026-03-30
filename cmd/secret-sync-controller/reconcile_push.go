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

func (c *controller) reconcile(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		c.logVerbosef("skip reconcile source=%s/%s: %s is %q", src.Namespace, src.Name, labelSyncEnabled, src.Labels[labelSyncEnabled])
		return nil
	}
	c.metrics.reconcileTotal.Add(1)

	targets, err := parseTargets(src.Annotations[annSyncTargets])
	if err != nil {
		msg := fmt.Sprintf("invalid %s annotation: %v", annSyncTargets, err)
		c.logVerbosef("reject reconcile source=%s/%s: %s", src.Namespace, src.Name, msg)
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
			c.logVerbosef("block target source=%s/%s target=%s: %v", src.Namespace, src.Name, target.ID(), targetErr)
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

func (c *controller) handleDelete(ctx context.Context, src *corev1.Secret) error {
	if src.Labels[labelSyncEnabled] != "true" {
		c.logVerbosef("skip delete source=%s/%s: %s is %q", src.Namespace, src.Name, labelSyncEnabled, src.Labels[labelSyncEnabled])
		return nil
	}
	c.metrics.deleteTotal.Add(1)

	rawDeletePolicy := src.Annotations[annDeletePolicy]
	deletePolicy := normalizeDeletePolicy(rawDeletePolicy)
	if strings.TrimSpace(rawDeletePolicy) != "" && deletePolicy == "" {
		c.logVerbosef("invalid delete policy source=%s/%s: %q, falling back to default %q", src.Namespace, src.Name, rawDeletePolicy, c.cfg.defaultDeletePolicy)
	}
	if deletePolicy == "" {
		deletePolicy = c.cfg.defaultDeletePolicy
	}
	if deletePolicy == "retain" {
		c.logVerbosef("retain delete source=%s/%s due to delete policy %q", src.Namespace, src.Name, deletePolicy)
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
			c.logVerbosef("ownership conflict on delete source=%s/%s target=%s: %s", src.Namespace, src.Name, target.ID(), msg)
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

func (c *controller) validateTargetForSource(src *corev1.Secret, target syncTarget) error {
	if target.Kind != targetKindCluster {
		return fmt.Errorf("target %q is blocked: push mode only allows kind=%s", target.ID(), targetKindCluster)
	}
	if target.Namespace == src.Namespace {
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
