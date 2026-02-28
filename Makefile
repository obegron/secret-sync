.DEFAULT_GOAL := build

BINARY ?= vcluster-secret-sync-controller
IMAGE ?= ghcr.io/company/vcluster-secret-sync-controller:latest

INTEGRATION_CLUSTER ?= vcluster-secret-sync-it
INTEGRATION_IMAGE ?= vcluster-secret-sync-controller:it
INTEGRATION_TMP_DIR ?= .tmp/integration
VCLUSTER_NAME ?= tenant-a-dev01
VCLUSTER_NAMESPACE ?= vcluster-tenant-a-dev01
VCLUSTER_KUBECONFIG_SECRET ?= vc-$(VCLUSTER_NAME)
SOURCE_NAMESPACE ?= tenant-host-ns
TARGET_NAMESPACE ?= app-runtime
SOURCE_SECRET_NAME ?= app-db-secret
CONTROLLER_NAMESPACE ?= vcluster-secret-sync-system

.PHONY: help tidy fmt vet build test docker-build run check-tools integration-up integration-test integration-down

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; print "Targets:"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tidy: ## Run go mod tidy
	go mod tidy

fmt: ## Format Go code
	gofmt -w ./cmd

vet: ## Run go vet
	go vet ./...

build: ## Build controller binary (default)
	go build -o $(BINARY) ./cmd/vcluster-secret-sync-controller

test: ## Run unit tests
	go test ./...

docker-build: ## Build controller container image
	docker build -t $(IMAGE) .

run: ## Run controller locally
	go run ./cmd/vcluster-secret-sync-controller

check-tools: ## Verify required integration tools are installed
	@for cmd in docker k3d kubectl helm curl; do \
		command -v $$cmd >/dev/null 2>&1 || { echo "missing required command: $$cmd"; exit 1; }; \
	done

integration-up: check-tools ## Create local k3d + vcluster + controller integration environment
	@set -euo pipefail; \
	if ! k3d cluster list | awk 'NR>1 {print $$1}' | grep -qx "$(INTEGRATION_CLUSTER)"; then \
		k3d cluster create "$(INTEGRATION_CLUSTER)"; \
	fi; \
	kubectl config use-context "k3d-$(INTEGRATION_CLUSTER)" >/dev/null; \
	docker build -t "$(INTEGRATION_IMAGE)" .; \
	k3d image import -c "$(INTEGRATION_CLUSTER)" "$(INTEGRATION_IMAGE)"; \
	mkdir -p "$(INTEGRATION_TMP_DIR)/vcluster" "$(INTEGRATION_TMP_DIR)/bin"; \
	REAL_HELM=$$(command -v helm); \
	printf '%s\n' '#!/bin/sh' 'if [ "$${1:-}" = "version" ]; then' '  echo v3.14.0' '  exit 0' 'fi' 'exec '"$$REAL_HELM"' "$$@"' > "$(INTEGRATION_TMP_DIR)/bin/helm"; \
	chmod +x "$(INTEGRATION_TMP_DIR)/bin/helm"; \
	sed -e 's|__VCLUSTER_NAME__|$(VCLUSTER_NAME)|g' -e 's|__VCLUSTER_NAMESPACE__|$(VCLUSTER_NAMESPACE)|g' \
		deploy/integration/vcluster/kustomization.yaml.tmpl > "$(INTEGRATION_TMP_DIR)/vcluster/kustomization.yaml"; \
	kubectl create namespace "$(VCLUSTER_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -; \
	PATH="$$PWD/$(INTEGRATION_TMP_DIR)/bin:$$PATH" kubectl kustomize --enable-helm "$(INTEGRATION_TMP_DIR)/vcluster" | kubectl apply -f -; \
	for i in $$(seq 1 120); do \
		if kubectl -n "$(VCLUSTER_NAMESPACE)" get secret "$(VCLUSTER_KUBECONFIG_SECRET)" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	kubectl -n "$(VCLUSTER_NAMESPACE)" get secret "$(VCLUSTER_KUBECONFIG_SECRET)" >/dev/null; \
	kubectl -n "$(VCLUSTER_NAMESPACE)" get secret "$(VCLUSTER_KUBECONFIG_SECRET)" -o jsonpath='{.data.config}' | base64 -d > "$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig"; \
	VCLUSTER_POD_IP=$$(kubectl -n "$(VCLUSTER_NAMESPACE)" get pod "$(VCLUSTER_NAME)-0" -o jsonpath='{.status.podIP}'); \
	awk -v ip="$$VCLUSTER_POD_IP" '{ if ($$1 == "server:") { print "    server: https://" ip ":8443"; print "    tls-server-name: kubernetes"; next } print }' "$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" > "$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME).kubeconfig"; \
	kubectl -n "$(VCLUSTER_NAMESPACE)" port-forward "svc/$(VCLUSTER_NAME)" 8443:443 > "$(INTEGRATION_TMP_DIR)/port-forward.log" 2>&1 & \
	PF_PID=$$!; \
	trap 'kill $$PF_PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 30); do \
		if KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl get namespace default >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 1; \
	done; \
	kubectl apply -f deploy/base/namespace.yaml; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" create secret generic vcluster-kubeconfigs \
		--from-file="$(VCLUSTER_NAME).kubeconfig=$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME).kubeconfig" \
		--dry-run=client -o yaml | kubectl apply -f -; \
	kubectl kustomize --load-restrictor=LoadRestrictionsNone deploy/base | kubectl apply -f -; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" set image deployment/vcluster-secret-sync-controller controller="$(INTEGRATION_IMAGE)"; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" rollout restart deployment/vcluster-secret-sync-controller; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" rollout status deployment/vcluster-secret-sync-controller --timeout=180s; \
	kubectl create namespace "$(SOURCE_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -; \
	KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl create namespace "$(TARGET_NAMESPACE)" --dry-run=client -o yaml | KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl apply -f -; \
	kubectl -n "$(SOURCE_NAMESPACE)" create secret generic "$(SOURCE_SECRET_NAME)" \
		--from-literal=username=appuser \
		--from-literal=password=supersecret \
		--dry-run=client -o yaml | kubectl apply -f -; \
	kubectl -n "$(SOURCE_NAMESPACE)" label secret "$(SOURCE_SECRET_NAME)" obegron.github.io/sync-to-vcluster=true --overwrite; \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$(SOURCE_SECRET_NAME)" \
		obegron.github.io/vcluster-name="$(VCLUSTER_NAME)" \
		obegron.github.io/vcluster-namespace="$(TARGET_NAMESPACE)" \
		obegron.github.io/delete-policy=delete --overwrite; \
	kill $$PF_PID >/dev/null 2>&1 || true; \
	trap - EXIT

integration-test: integration-up ## Run full integration test and validate synced secret data
	@set -euo pipefail; \
	kubectl -n "$(VCLUSTER_NAMESPACE)" port-forward "svc/$(VCLUSTER_NAME)" 8443:443 > "$(INTEGRATION_TMP_DIR)/port-forward-test.log" 2>&1 & \
	PF_PID=$$!; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" port-forward deployment/vcluster-secret-sync-controller 18080:8080 > "$(INTEGRATION_TMP_DIR)/port-forward-controller.log" 2>&1 & \
	HPF_PID=$$!; \
	trap 'kill $$PF_PID >/dev/null 2>&1 || true; kill $$HPF_PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 20); do \
		if curl -fsS http://127.0.0.1:18080/readyz >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 1; \
	done; \
	curl -fsS http://127.0.0.1:18080/healthz >/dev/null; \
	curl -fsS http://127.0.0.1:18080/readyz >/dev/null; \
	curl -fsS http://127.0.0.1:18080/metrics | grep -q 'secret_sync_reconcile_total'; \
	for i in $$(seq 1 30); do \
		if KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl -n "$(TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl -n "$(TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" >/dev/null; \
	username=$$(KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl -n "$(TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.username}' | base64 -d); \
	password=$$(KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl -n "$(TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$username" = "appuser" ]; \
	[ "$$password" = "supersecret" ]; \
	reasons=$$(kubectl -n "$(SOURCE_NAMESPACE)" get events --field-selector involvedObject.kind=Secret,involvedObject.name="$(SOURCE_SECRET_NAME)" -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}'); \
	echo "$$reasons" | grep -Eq 'SyncCreated|SyncUpdated'; \
	pw_b64=$$(printf 'supersecret2' | base64 | tr -d '\n'); \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$(SOURCE_SECRET_NAME)" --type merge -p "{\"data\":{\"password\":\"$$pw_b64\"}}"; \
	for i in $$(seq 1 30); do \
		password2=$$(KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl -n "$(TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || true); \
		if [ "$$password2" = "supersecret2" ]; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	password2=$$(KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl -n "$(TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$password2" = "supersecret2" ]; \
	reasons2=$$(kubectl -n "$(SOURCE_NAMESPACE)" get events --field-selector involvedObject.kind=Secret,involvedObject.name="$(SOURCE_SECRET_NAME)" -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}'); \
	echo "$$reasons2" | grep -q 'SyncUpdated'; \
	echo "integration test passed"; \
	kill $$PF_PID >/dev/null 2>&1 || true; \
	kill $$HPF_PID >/dev/null 2>&1 || true; \
	trap - EXIT

integration-down: check-tools ## Delete integration cluster and temp files
	@set -euo pipefail; \
	if k3d cluster list | awk 'NR>1 {print $$1}' | grep -qx "$(INTEGRATION_CLUSTER)"; then \
		k3d cluster delete "$(INTEGRATION_CLUSTER)"; \
	fi; \
	rm -rf "$(INTEGRATION_TMP_DIR)"
