.DEFAULT_GOAL := build

BINARY ?= secret-sync-controller
VERSION := $(shell sed -n -E 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' cmd/secret-sync-controller/main.go | head -n 1)
IMAGE_NAME ?= obegron/secret-sync-controller
IMAGE ?= $(IMAGE_NAME):$(VERSION)
PLATFORMS ?= linux/amd64,linux/arm64
TRIVY_IMAGE ?= aquasec/trivy:0.69.1
TRIVY_SEVERITY ?= HIGH,CRITICAL
TRIVY_EXIT_CODE ?= 1

INTEGRATION_CLUSTER ?= secret-sync-it
INTEGRATION_IMAGE ?= secret-sync-controller:it
INTEGRATION_TMP_DIR ?= .tmp/integration
VCLUSTER_NAME ?= tenant-a-dev01
VCLUSTER_NAMESPACE ?= vcluster-tenant-a-dev01
VCLUSTER_KUBECONFIG_SECRET ?= vc-$(VCLUSTER_NAME)
SOURCE_NAMESPACE ?= tenant-host-ns
TARGET_NAMESPACE ?= app-runtime
CLUSTER_TARGET_NAMESPACE ?= shared-runtime
CLUSTER_TARGET_NAMESPACE_2 ?= shared-runtime-2
SOURCE_SECRET_NAME ?= app-db-secret
CONTROLLER_NAMESPACE ?= secret-sync-system

.PHONY: help tidy fmt vet build test docker-build-local docker-build docker-push show-version scan-image run clean check-tools integration-up integration-test integration-down

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; print "Targets:"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tidy: ## Run go mod tidy
	go mod tidy

fmt: ## Format Go code
	gofmt -w ./cmd

vet: ## Run go vet
	go vet ./...

build: ## Build controller binary (default)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/secret-sync-controller

test: ## Run unit tests
	go test ./...

docker-build-local: ## Build local container image for current architecture
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-build: ## Build multi-arch container image (no push)
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-push: ## Build and push multi-arch container image
	docker buildx build --platform $(PLATFORMS) --provenance=true --sbom=true -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --push

show-version: ## Print application version
	@echo $(VERSION)

scan-image: docker-build-local ## Scan local container image with Trivy
	@mkdir -p .tmp/trivy-cache
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(PWD)/.tmp/trivy-cache:/root/.cache/" \
		"$(TRIVY_IMAGE)" image \
		--skip-version-check \
		--severity "$(TRIVY_SEVERITY)" \
		--exit-code "$(TRIVY_EXIT_CODE)" \
		--no-progress \
		"$(IMAGE_NAME):$(VERSION)"

run: ## Run controller locally
	go run ./cmd/secret-sync-controller

clean: ## Remove built binaries
	rm -f $(BINARY)

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
	kubectl -n "$(CONTROLLER_NAMESPACE)" set image deployment/secret-sync-controller controller="$(INTEGRATION_IMAGE)"; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" rollout status deployment/secret-sync-controller --timeout=180s; \
	kubectl create namespace "$(SOURCE_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -; \
	KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl create namespace "$(TARGET_NAMESPACE)" --dry-run=client -o yaml | KUBECONFIG="$(INTEGRATION_TMP_DIR)/$(VCLUSTER_NAME)-local.kubeconfig" kubectl apply -f -; \
	kubectl create namespace "$(CLUSTER_TARGET_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -; \
	kubectl create namespace "$(CLUSTER_TARGET_NAMESPACE_2)" --dry-run=client -o yaml | kubectl apply -f -; \
	kubectl -n "$(SOURCE_NAMESPACE)" create secret generic "$(SOURCE_SECRET_NAME)" \
		--from-literal=username=appuser \
		--from-literal=password=supersecret \
		--dry-run=client -o yaml | kubectl apply -f -; \
	TARGETS_JSON=$$(printf '[{"kind":"vcluster","vcluster":"%s","namespace":"%s"},{"kind":"cluster","namespace":"%s"},{"kind":"cluster","namespace":"%s"}]' "$(VCLUSTER_NAME)" "$(TARGET_NAMESPACE)" "$(CLUSTER_TARGET_NAMESPACE)" "$(CLUSTER_TARGET_NAMESPACE_2)"); \
	FORCE_TS=$$(date +%s); \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$(SOURCE_SECRET_NAME)" \
		obegron.github.io/secret-sync-targets="$$TARGETS_JSON" \
		obegron.github.io/force-sync-ts="$$FORCE_TS" \
		obegron.github.io/delete-policy=delete --overwrite; \
	kubectl -n "$(SOURCE_NAMESPACE)" label secret "$(SOURCE_SECRET_NAME)" obegron.github.io/secret-sync-enabled=true --overwrite; \
	kill $$PF_PID >/dev/null 2>&1 || true; \
	trap - EXIT

integration-test: integration-up ## Run full integration test and validate synced secret data
	@set -euo pipefail; \
	kubectl -n "$(VCLUSTER_NAMESPACE)" port-forward "svc/$(VCLUSTER_NAME)" 8443:443 > "$(INTEGRATION_TMP_DIR)/port-forward-test.log" 2>&1 & \
	PF_PID=$$!; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" port-forward deployment/secret-sync-controller 18080:8080 > "$(INTEGRATION_TMP_DIR)/port-forward-controller.log" 2>&1 & \
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
	cluster_username=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.username}' | base64 -d); \
	cluster_password=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster_username" = "appuser" ]; \
	[ "$$cluster_password" = "supersecret" ]; \
	cluster2_username=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.username}' | base64 -d); \
	cluster2_password=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster2_username" = "appuser" ]; \
	[ "$$cluster2_password" = "supersecret" ]; \
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
	cluster_password2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster_password2" = "supersecret2" ]; \
	cluster2_password2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster2_password2" = "supersecret2" ]; \
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
