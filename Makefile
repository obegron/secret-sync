.DEFAULT_GOAL := build

BINARY ?= secret-sync-controller
OIDC_HELPER_BINARY ?= oidc-helper
VERSION_FILE ?= VERSION
VERSION ?= $(shell cat $(VERSION_FILE))
ifeq ($(strip $(VERSION)),)
VERSION := $(shell cat $(VERSION_FILE))
endif
IMAGE_NAME ?= docker.io/obegron/secret-sync-controller
IMAGE ?= $(IMAGE_NAME):$(VERSION)
PLATFORMS ?= linux/amd64,linux/arm64
TRIVY_IMAGE ?= aquasec/trivy:0.69.1
TRIVY_SEVERITY ?= HIGH,CRITICAL
TRIVY_EXIT_CODE ?= 1

INTEGRATION_CLUSTER ?= secret-sync-it
INTEGRATION_IMAGE ?= secret-sync-controller:it
INTEGRATION_TMP_DIR ?= .tmp/integration
SOURCE_NAMESPACE ?= tenant-host-ns
CLUSTER_TARGET_NAMESPACE ?= shared-runtime
CLUSTER_TARGET_NAMESPACE_2 ?= shared-runtime-2
SOURCE_SECRET_NAME ?= app-db-secret
CONTROLLER_NAMESPACE ?= secret-sync-system

.PHONY: help tidy fmt vet build build-oidc-helper test docker-build-local docker-build docker-push show-version set-version scan-image run run-oidc-helper clean check-tools integration-up integration-test integration-test-pull integration-test-collision integration-down

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; print "Targets:"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tidy: ## Run go mod tidy
	go mod tidy

fmt: ## Format Go code
	gofmt -w ./cmd

vet: ## Run go vet
	go vet ./...

build: ## Build controller binary (default)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" -o $(BINARY) ./cmd/secret-sync-controller

build-oidc-helper: ## Build OIDC helper binary
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" -o $(OIDC_HELPER_BINARY) ./cmd/oidc-helper

test: ## Run unit tests
	go test ./...

docker-build-local: ## Build local container image for current architecture
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-build: ## Build multi-arch container image (no push)
	docker buildx build --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-push: ## Build and push multi-arch container image
	docker buildx build --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) --provenance=true --sbom=true -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --push

show-version: ## Print application version
	@echo $(VERSION)

set-version: ## Set VERSION and sync chart version/appVersion (usage: make set-version VERSION=0.1.1)
	@test -n "$(VERSION)" || { echo "VERSION is required"; exit 1; }
	@printf '%s\n' "$(VERSION)" > "$(VERSION_FILE)"
	@sed -E -i 's/^version: .*/version: $(VERSION)/' charts/secret-sync-controller/Chart.yaml
	@sed -E -i 's/^appVersion: .*/appVersion: "$(VERSION)"/' charts/secret-sync-controller/Chart.yaml
	@sed -E -i 's|^[[:space:]]*image: .*|          image: $(IMAGE_NAME):$(VERSION)|' deploy/base/deployment.yaml
	@echo "Set version to $(VERSION)"

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
	go run -ldflags="-X main.Version=$(VERSION)" ./cmd/secret-sync-controller

run-oidc-helper: ## Run OIDC helper locally
	go run -ldflags="-X main.Version=$(VERSION)" ./cmd/oidc-helper

clean: ## Remove built binaries
	rm -f $(BINARY) $(OIDC_HELPER_BINARY)

check-tools: ## Verify required integration tools are installed
	@for cmd in docker k3d kubectl curl; do \
		command -v $$cmd >/dev/null 2>&1 || { echo "missing required command: $$cmd"; exit 1; }; \
	done

integration-up: check-tools ## Create local k3d + controller integration environment
	@set -euo pipefail; \
	if ! k3d cluster list | awk 'NR>1 {print $$1}' | grep -qx "$(INTEGRATION_CLUSTER)"; then \
		k3d cluster create "$(INTEGRATION_CLUSTER)"; \
	fi; \
	kubectl config use-context "k3d-$(INTEGRATION_CLUSTER)" >/dev/null; \
	docker build -t "$(INTEGRATION_IMAGE)" .; \
	k3d image import -c "$(INTEGRATION_CLUSTER)" "$(INTEGRATION_IMAGE)"; \
	mkdir -p "$(INTEGRATION_TMP_DIR)"; \
	kubectl apply -f deploy/base/namespace.yaml; \
	kubectl kustomize --load-restrictor=LoadRestrictionsNone deploy/base | kubectl apply -f -; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" set image deployment/secret-sync-controller controller="$(INTEGRATION_IMAGE)"; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" rollout status deployment/secret-sync-controller --timeout=180s; \
	kubectl create namespace "$(SOURCE_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -; \
	kubectl create namespace "$(CLUSTER_TARGET_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -; \
	kubectl create namespace "$(CLUSTER_TARGET_NAMESPACE_2)" --dry-run=client -o yaml | kubectl apply -f -; \
	kubectl -n "$(SOURCE_NAMESPACE)" delete secret "$(SOURCE_SECRET_NAME)" --ignore-not-found; \
	kubectl -n "$(SOURCE_NAMESPACE)" create secret generic "$(SOURCE_SECRET_NAME)" \
		--from-literal=username=appuser \
		--from-literal=password=supersecret \
		--dry-run=client -o yaml | kubectl apply -f -; \
	TARGETS_JSON=$$(printf '[{"kind":"cluster","namespace":"%s"},{"kind":"cluster","namespace":"%s","name":"%s-alt"}]' "$(CLUSTER_TARGET_NAMESPACE)" "$(CLUSTER_TARGET_NAMESPACE_2)" "$(SOURCE_SECRET_NAME)"); \
	FORCE_TS=$$(date +%s); \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$(SOURCE_SECRET_NAME)" \
		obegron.github.io/secret-sync-targets="$$TARGETS_JSON" \
		obegron.github.io/force-sync-ts="$$FORCE_TS" \
		obegron.github.io/delete-policy=delete --overwrite; \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$(SOURCE_SECRET_NAME)" --type merge -p '{"metadata":{"labels":{"obegron.github.io/secret-sync-enabled":"true"}}}'

integration-test: integration-up ## Run full integration test and validate synced secret data
	@set -euo pipefail; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" port-forward deployment/secret-sync-controller 18080:8080 > "$(INTEGRATION_TMP_DIR)/port-forward-controller.log" 2>&1 & \
	HPF_PID=$$!; \
	trap 'kill $$HPF_PID >/dev/null 2>&1 || true' EXIT; \
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
		if kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	SOURCE_SECRET_ALT_NAME="$(SOURCE_SECRET_NAME)-alt"; \
	cluster_username=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.username}' | base64 -d); \
	cluster_password=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster_username" = "appuser" ]; \
	[ "$$cluster_password" = "supersecret" ]; \
	cluster2_username=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$SOURCE_SECRET_ALT_NAME" -o jsonpath='{.data.username}' | base64 -d); \
	cluster2_password=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$SOURCE_SECRET_ALT_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster2_username" = "appuser" ]; \
	[ "$$cluster2_password" = "supersecret" ]; \
	reasons=$$(kubectl -n "$(SOURCE_NAMESPACE)" get events --field-selector involvedObject.kind=Secret,involvedObject.name="$(SOURCE_SECRET_NAME)" -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}'); \
	echo "$$reasons" | grep -Eq 'SyncCreated|SyncUpdated'; \
	pw_b64=$$(printf 'supersecret2' | base64 | tr -d '\n'); \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$(SOURCE_SECRET_NAME)" --type merge -p "{\"data\":{\"password\":\"$$pw_b64\"}}"; \
	for i in $$(seq 1 30); do \
		cluster_password2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || true); \
		cluster2_password2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$SOURCE_SECRET_ALT_NAME" -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || true); \
		if [ "$$cluster_password2" = "supersecret2" ] && [ "$$cluster2_password2" = "supersecret2" ]; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	cluster_password2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$(SOURCE_SECRET_NAME)" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster_password2" = "supersecret2" ]; \
	cluster2_password2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$SOURCE_SECRET_ALT_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$cluster2_password2" = "supersecret2" ]; \
	reasons2=$$(kubectl -n "$(SOURCE_NAMESPACE)" get events --field-selector involvedObject.kind=Secret,involvedObject.name="$(SOURCE_SECRET_NAME)" -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}'); \
	echo "$$reasons2" | grep -q 'SyncUpdated'; \
	echo "integration test passed"; \
	kill $$HPF_PID >/dev/null 2>&1 || true; \
	trap - EXIT

integration-test-pull: integration-up ## Run pull-mode integration test with static OIDC helper
	@set -euo pipefail; \
	mkdir -p "$(INTEGRATION_TMP_DIR)"; \
		kubectl -n "$(CONTROLLER_NAMESPACE)" set env deployment/secret-sync-controller \
			SYNC_MODE=pull \
			SOURCE_NAMESPACE="$(SOURCE_NAMESPACE)" \
			TARGET_NAMESPACE="$(CLUSTER_TARGET_NAMESPACE)" \
			HOST_API_SERVER="" \
			PULL_NAMESPACE_ISOLATION=false \
			ALLOWED_SYNC_TARGETS=""; \
	kubectl -n "$(CONTROLLER_NAMESPACE)" rollout status deployment/secret-sync-controller --timeout=180s; \
	printf '%s\n' '{"issuer":"https://kubernetes.default.svc","jwks_uri":"https://placeholder.invalid/openid/v1/jwks","response_types_supported":["id_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}' > "$(INTEGRATION_TMP_DIR)/static-oidc-config.json"; \
	printf '%s\n' '{"keys":[]}' > "$(INTEGRATION_TMP_DIR)/static-jwks.json"; \
	OIDC_HELPER_PORT=19191; \
	ENVIRONMENT_BASE_URL="http://127.0.0.1:$$OIDC_HELPER_PORT" \
	OIDC_MODE=static \
	PORT=$$OIDC_HELPER_PORT \
	STATIC_OIDC_CONFIG_FILE="$(INTEGRATION_TMP_DIR)/static-oidc-config.json" \
	STATIC_JWKS_FILE="$(INTEGRATION_TMP_DIR)/static-jwks.json" \
	go run -ldflags="-X main.Version=$(VERSION)" ./cmd/oidc-helper > "$(INTEGRATION_TMP_DIR)/oidc-helper.log" 2>&1 & \
	OIDC_PID=$$!; \
	trap 'kill $$OIDC_PID >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 20); do \
		if curl -fsS "http://127.0.0.1:$$OIDC_HELPER_PORT/health" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 1; \
	done; \
	curl -fsS "http://127.0.0.1:$$OIDC_HELPER_PORT/health" >/dev/null; \
	curl -fsS "http://127.0.0.1:$$OIDC_HELPER_PORT/.well-known/openid-configuration" > "$(INTEGRATION_TMP_DIR)/served-oidc-config.json"; \
	grep -q '"issuer":"https://kubernetes.default.svc"' "$(INTEGRATION_TMP_DIR)/served-oidc-config.json"; \
	grep -q "\"jwks_uri\":\"http://127.0.0.1:$$OIDC_HELPER_PORT/openid/v1/jwks\"" "$(INTEGRATION_TMP_DIR)/served-oidc-config.json"; \
	curl -fsS "http://127.0.0.1:$$OIDC_HELPER_PORT/openid/v1/jwks" | grep -q '"keys"'; \
	PULL_SECRET_NAME="$(SOURCE_SECRET_NAME)-pull"; \
	kubectl -n "$(SOURCE_NAMESPACE)" delete secret "$$PULL_SECRET_NAME" --ignore-not-found; \
	kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" delete secret "$$PULL_SECRET_NAME" --ignore-not-found; \
	kubectl -n "$(SOURCE_NAMESPACE)" create secret generic "$$PULL_SECRET_NAME" \
		--from-literal=username=pulluser \
		--from-literal=password=pullsecret \
		--dry-run=client -o yaml | kubectl apply -f -; \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$$PULL_SECRET_NAME" --type merge -p '{"metadata":{"labels":{"obegron.github.io/secret-sync-enabled":"true"}}}'; \
	PULL_TARGETS_JSON=$$(printf '[{"kind":"cluster","namespace":"%s"},{"kind":"cluster","namespace":"%s"}]' "$(CLUSTER_TARGET_NAMESPACE)" "$(CLUSTER_TARGET_NAMESPACE_2)"); \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$$PULL_SECRET_NAME" obegron.github.io/secret-sync-targets="$$PULL_TARGETS_JSON" --overwrite; \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$$PULL_SECRET_NAME" obegron.github.io/delete-policy=delete --overwrite; \
	for i in $$(seq 1 30); do \
		if kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" >/dev/null 2>&1 && \
		   kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" >/dev/null; \
	kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" >/dev/null; \
	pull_user=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.username}' | base64 -d); \
	pull_pw=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	pull_user2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.username}' | base64 -d); \
	pull_pw2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$pull_user" = "pulluser" ]; \
	[ "$$pull_pw" = "pullsecret" ]; \
	[ "$$pull_user2" = "pulluser" ]; \
	[ "$$pull_pw2" = "pullsecret" ]; \
	pw_b64=$$(printf 'pullsecret2' | base64 | tr -d '\n'); \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$$PULL_SECRET_NAME" --type merge -p "{\"data\":{\"password\":\"$$pw_b64\"}}"; \
	for i in $$(seq 1 30); do \
		pull_pw2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || true); \
		pull_pw3=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || true); \
		if [ "$$pull_pw2" = "pullsecret2" ] && [ "$$pull_pw3" = "pullsecret2" ]; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	pull_pw2=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	pull_pw3=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$pull_pw2" = "pullsecret2" ]; \
	[ "$$pull_pw3" = "pullsecret2" ]; \
	kubectl -n "$(SOURCE_NAMESPACE)" delete secret "$$PULL_SECRET_NAME"; \
	for i in $$(seq 1 30); do \
		if ! kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" >/dev/null 2>&1 && \
		   ! kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	! kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$PULL_SECRET_NAME" >/dev/null 2>&1; \
	! kubectl -n "$(CLUSTER_TARGET_NAMESPACE_2)" get secret "$$PULL_SECRET_NAME" >/dev/null 2>&1; \
	echo "integration pull test passed"; \
	kill $$OIDC_PID >/dev/null 2>&1 || true; \
	trap - EXIT

integration-test-collision: integration-up ## Run push-mode collision test for renamed targets
	@set -euo pipefail; \
	SECRET_A="$(SOURCE_SECRET_NAME)-a"; \
	SECRET_B="$(SOURCE_SECRET_NAME)-b"; \
	TARGET_NAME="$(SOURCE_SECRET_NAME)-shared"; \
	kubectl -n "$(SOURCE_NAMESPACE)" delete secret "$$SECRET_A" "$$SECRET_B" --ignore-not-found; \
	kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" delete secret "$$TARGET_NAME" --ignore-not-found; \
	kubectl -n "$(SOURCE_NAMESPACE)" create secret generic "$$SECRET_A" \
		--from-literal=username=usera \
		--from-literal=password=pwa \
		--dry-run=client -o yaml | kubectl apply -f -; \
	kubectl -n "$(SOURCE_NAMESPACE)" create secret generic "$$SECRET_B" \
		--from-literal=username=userb \
		--from-literal=password=pwb \
		--dry-run=client -o yaml | kubectl apply -f -; \
	TARGET_A=$$(printf '[{"kind":"cluster","namespace":"%s","name":"%s"}]' "$(CLUSTER_TARGET_NAMESPACE)" "$$TARGET_NAME"); \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$$SECRET_A" \
		obegron.github.io/secret-sync-targets="$$TARGET_A" \
		obegron.github.io/delete-policy=delete --overwrite; \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$$SECRET_A" --type merge -p '{"metadata":{"labels":{"obegron.github.io/secret-sync-enabled":"true"}}}'; \
	for i in $$(seq 1 30); do \
		if kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$TARGET_NAME" >/dev/null 2>&1; then \
			break; \
		fi; \
		sleep 2; \
	done; \
	kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$TARGET_NAME" >/dev/null; \
	TARGET_B=$$(printf '[{"kind":"cluster","namespace":"%s","name":"%s"}]' "$(CLUSTER_TARGET_NAMESPACE)" "$$TARGET_NAME"); \
	kubectl -n "$(SOURCE_NAMESPACE)" annotate secret "$$SECRET_B" \
		obegron.github.io/secret-sync-targets="$$TARGET_B" \
		obegron.github.io/delete-policy=delete --overwrite; \
	kubectl -n "$(SOURCE_NAMESPACE)" patch secret "$$SECRET_B" --type merge -p '{"metadata":{"labels":{"obegron.github.io/secret-sync-enabled":"true"}}}'; \
	sleep 4; \
	target_user=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$TARGET_NAME" -o jsonpath='{.data.username}' | base64 -d); \
	target_pw=$$(kubectl -n "$(CLUSTER_TARGET_NAMESPACE)" get secret "$$TARGET_NAME" -o jsonpath='{.data.password}' | base64 -d); \
	[ "$$target_user" = "usera" ]; \
	[ "$$target_pw" = "pwa" ]; \
	reasons_b=$$(kubectl -n "$(SOURCE_NAMESPACE)" get events --field-selector involvedObject.kind=Secret,involvedObject.name="$$SECRET_B" -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}'); \
	echo "$$reasons_b" | grep -q 'SyncTargetOwnershipConflict'; \
	echo "integration collision test passed"

integration-down: check-tools ## Delete integration cluster and temp files
	@set -euo pipefail; \
	if k3d cluster list | awk 'NR>1 {print $$1}' | grep -qx "$(INTEGRATION_CLUSTER)"; then \
		k3d cluster delete "$(INTEGRATION_CLUSTER)"; \
	fi; \
	rm -rf "$(INTEGRATION_TMP_DIR)"
