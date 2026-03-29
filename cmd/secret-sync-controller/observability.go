package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

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
	bridgePollSuccess  atomic.Uint64
	bridgePollErrors   atomic.Uint64
	lastSuccessUnix    atomic.Int64
	lastErrorUnix      atomic.Int64
	lastDurationNanos  atomic.Int64
	lastErrorCategory  atomic.Value
}

func (c *controller) recordSuccess(duration time.Duration) {
	c.metrics.lastSuccessUnix.Store(time.Now().Unix())
	c.metrics.lastDurationNanos.Store(duration.Nanoseconds())
}

func (c *controller) recordError(category string) {
	c.metrics.lastErrorUnix.Store(time.Now().Unix())
	if strings.TrimSpace(category) != "" {
		c.metrics.lastErrorCategory.Store(category)
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

func (c *controller) handleVersion(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(Version + "\n"))
}

func (c *controller) handleStatus(w http.ResponseWriter, _ *http.Request) {
	var lastError string
	if value := c.metrics.lastErrorCategory.Load(); value != nil {
		lastError, _ = value.(string)
	}

	payload := map[string]interface{}{
		"service":                controllerName,
		"version":                Version,
		"uptime_seconds":         time.Since(c.startedAt).Seconds(),
		"ready":                  c.ready.Load(),
		"sync_mode":              c.cfg.syncMode,
		"source_provider":        c.cfg.sourceProvider,
		"source_namespace":       c.cfg.sourceNamespace,
		"target_namespace":       c.cfg.targetNamespace,
		"bridge_base_url":        c.cfg.bridgeBaseURL,
		"last_success_unixtime":  c.metrics.lastSuccessUnix.Load(),
		"last_error_unixtime":    c.metrics.lastErrorUnix.Load(),
		"last_error_category":    lastError,
		"last_duration_seconds":  float64(c.metrics.lastDurationNanos.Load()) / float64(time.Second),
		"reconcile_total":        c.metrics.reconcileTotal.Load(),
		"reconcile_errors_total": c.metrics.reconcileErrors.Load(),
		"delete_total":           c.metrics.deleteTotal.Load(),
		"delete_errors_total":    c.metrics.deleteErrors.Load(),
		"sync_created_total":     c.metrics.syncCreatedTotal.Load(),
		"sync_updated_total":     c.metrics.syncUpdatedTotal.Load(),
		"sync_recreated_total":   c.metrics.syncRecreatedTotal.Load(),
		"sync_deleted_total":     c.metrics.syncDeletedTotal.Load(),
		"bridge_poll_successes":  c.metrics.bridgePollSuccess.Load(),
		"bridge_poll_errors":     c.metrics.bridgePollErrors.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
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
	fmt.Fprintf(w, "secret_sync_bridge_poll_success_total %d\n", c.metrics.bridgePollSuccess.Load())
	fmt.Fprintf(w, "secret_sync_bridge_poll_error_total %d\n", c.metrics.bridgePollErrors.Load())
	fmt.Fprintf(w, "secret_sync_last_success_unixtime %d\n", c.metrics.lastSuccessUnix.Load())
	fmt.Fprintf(w, "secret_sync_last_error_unixtime %d\n", c.metrics.lastErrorUnix.Load())
	fmt.Fprintf(w, "secret_sync_last_duration_seconds %f\n", float64(c.metrics.lastDurationNanos.Load())/float64(time.Second))
	fmt.Fprintf(w, "secret_sync_ready %d\n", boolToMetric(c.ready.Load()))
	fmt.Fprintf(w, "secret_sync_mode_info{mode=%q,source_provider=%q} 1\n", c.cfg.syncMode, c.cfg.sourceProvider)
}

func boolToMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
