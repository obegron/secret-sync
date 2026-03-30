package main

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *controller) emitWarningEvent(ctx context.Context, src *corev1.Secret, reason, message string) {
	c.emitEvent(ctx, src, corev1.EventTypeWarning, reason, message)
}

func (c *controller) emitNormalEvent(ctx context.Context, src *corev1.Secret, reason, message string) {
	c.emitEvent(ctx, src, corev1.EventTypeNormal, reason, message)
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

func (c *controller) logVerbosef(format string, args ...interface{}) {
	if !c.cfg.logVerbose {
		return
	}
	log.Printf(format, args...)
}

func (c *controller) emitEvent(ctx context.Context, src *corev1.Secret, eventType, reason, message string) {
	if c.cfg.syncMode == modePull && c.cfg.sourceProvider == sourceProviderBridge {
		return
	}
	eventClient := c.hostClient
	if c.cfg.syncMode == modePush && c.localClient != nil {
		eventClient = c.localClient
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

	if _, err := eventClient.CoreV1().Events(src.Namespace).Create(ctx, event, metav1.CreateOptions{}); err != nil {
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
