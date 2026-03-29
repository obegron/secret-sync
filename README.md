# secret-sync-controller

Secret sync controller with two explicit runtime modes:

- `push`: host-cluster source -> host-cluster target namespaces
- `pull`: host-cluster source -> local namespace in the cluster where the agent runs (vcluster pattern)

## Source Secret contract

Required label:

- `obegron.github.io/secret-sync-enabled=true`

Required annotation (`push` mode only):

- `obegron.github.io/secret-sync-targets` (JSON array)

Example target annotation value:

```json
[
  {"kind":"cluster","namespace":"shared-runtime"},
  {"kind":"cluster","namespace":"shared-runtime","name":"db-credentials"}
]
```

`name` is optional. When omitted, target secret name equals source name.

Optional annotation:

- `obegron.github.io/delete-policy=delete|retain` (default from `DEFAULT_DELETE_POLICY`)

## Runtime configuration

- `SYNC_MODE` (`push` or `pull`, default `push`)
- `HOST_KUBECONFIG` (optional)
- `POD_NAMESPACE` (set by Downward API in manifests/chart)
- `SOURCE_NAMESPACE`
- `TARGET_NAMESPACE` (used by `pull` mode; if unset, defaults to `POD_NAMESPACE`)
- `HOST_API_SERVER` (used by `pull` mode when `HOST_KUBECONFIG` is not set; if empty, falls back to in-cluster host API config)
- `HOST_TOKEN_FILE` (used by `pull` mode, default serviceaccount token path; token is re-read by client-go for rotation)
- `HOST_CA_FILE` (used by `pull` mode, default serviceaccount CA path)
- `DEFAULT_DELETE_POLICY` (`delete` or `retain`, default `delete`)
- `PULL_NAMESPACE_ISOLATION` (`true|false`, default `false`; pull mode only)
- `ALLOWED_SYNC_TARGETS` (optional JSON array allowlist; applies to push targets and pull targets)
- `METRICS_BIND_ADDRESS` (default `:8080`; serves `/healthz`, `/readyz`, `/version`, `/metrics`)

## Sync behavior

- Copies secret `type`, `data`, and `immutable`
- Target secret name is same as source name
- Adds managed annotations:
  - `obegron.github.io/managed-by=secret-sync-controller`
  - `obegron.github.io/source=<source-namespace>/<source-name>`
  - `obegron.github.io/checksum=<sha256>`
- Existing target secrets are only updated/deleted when owned by this controller and matching source annotation
- On source delete, controller deletes targets unless delete policy is `retain`

## Runtime modes

- `push`: watches source Secrets and syncs to `kind=cluster` targets only
- `pull`: watches source Secrets and mirrors into local-cluster target namespaces
  - pull reconcile/delete is processed via a rate-limited queue and transient failures are retried
  - if `secret-sync-targets` annotation is set on source Secret, pull mode uses those `kind=cluster` target namespaces in the local cluster
  - `TARGET_NAMESPACE` remains the fallback when annotation is not set

## Security modes

Namespace isolation mode (`PULL_NAMESPACE_ISOLATION=true`):

- intended for pull mode
- scopes source to pod namespace when `SOURCE_NAMESPACE` is unset

Platform mode (`PULL_NAMESPACE_ISOLATION=false`):

- set `SOURCE_NAMESPACE` and/or `ALLOWED_SYNC_TARGETS` to constrain blast radius

## Build and release

```bash
make show-version
make set-version VERSION=0.2.1
make docker-build
make docker-push
```

`set-version` updates:

- `VERSION`
- `charts/secret-sync-controller/Chart.yaml` `version`
- `charts/secret-sync-controller/Chart.yaml` `appVersion`
- `deploy/base/deployment.yaml` image tag

Run container vulnerability scan:

```bash
make scan-image
```

## Local integration test

```bash
make integration-test
make integration-test-pull
make integration-test-vcluster
make integration-test-collision
make integration-down
```

## Deploy

```bash
kubectl apply -k deploy/base
```

```bash
helm upgrade --install secret-sync-controller \
  ./charts/secret-sync-controller \
  --namespace secret-sync-system \
  --create-namespace
```

## Examples

- `deploy/examples/source-secret.yaml`
- `deploy/examples/source-secret-cluster-only.yaml`
- `deploy/examples/source-secret-many-namespaces.yaml`
- `deploy/examples/source-secret-renamed-target.yaml`

## OIDC helper (for vcluster pull auth)

`cmd/oidc-helper` provides an OIDC discovery/JWKS endpoint in two modes:

- `OIDC_MODE=proxy`: proxies Kubernetes `/.well-known/openid-configuration` and `/openid/v1/jwks`, rewriting `jwks_uri` to `ENVIRONMENT_BASE_URL`.
- `OIDC_MODE=static`: serves static OIDC config/JWKS from file or inline JSON (useful for integration tests without live upstream).

Build/run:

```bash
make build-oidc-helper
make run-oidc-helper
```

## Helm-only vcluster integration

`make integration-test-vcluster` creates a `vcluster` via the official Helm chart, extracts the generated kubeconfig from the `vc-<release>` Secret, port-forwards the vcluster API locally, and deploys `secret-sync-controller` inside the vcluster in `pull` mode.

The test mounts a host-cluster kubeconfig into the controller pod so it can watch source Secrets on the host cluster while writing synced Secrets into namespaces inside the vcluster.

## Manual vcluster test

Start from the working automated setup:

```bash
make integration-test-vcluster
```

That target creates:

- the k3d cluster
- the Helm-installed `vcluster`
- the `secret-sync-controller` release inside the `vcluster`
- `.tmp/integration/vcluster.kubeconfig`

If you want to reconnect to the `vcluster` manually later, re-export the defaults:

```bash
export VCLUSTER_NAME=secret-sync-vcluster
export VCLUSTER_NAMESPACE=secret-sync-vcluster
export VCLUSTER_CONNECT_PORT=18443
export VCLUSTER_KUBECONFIG=.tmp/integration/vcluster.kubeconfig
export SOURCE_NAMESPACE=secret-sync-vcluster
export TARGET_NAMESPACE=shared-runtime
```

Access the `vcluster` without the `vcluster` CLI:

```bash
kubectl -n "$VCLUSTER_NAMESPACE" port-forward service/"$VCLUSTER_NAME" "$VCLUSTER_CONNECT_PORT":443
```

In another shell:

```bash
kubectl -n "$VCLUSTER_NAMESPACE" get secret "vc-$VCLUSTER_NAME" -o jsonpath='{.data.config}' | base64 -d > .tmp/integration/vcluster.raw.kubeconfig
sed -E "s#server: https://[^[:space:]]+#server: https://localhost:$VCLUSTER_CONNECT_PORT#" \
  .tmp/integration/vcluster.raw.kubeconfig > "$VCLUSTER_KUBECONFIG"

KUBECONFIG="$VCLUSTER_KUBECONFIG" kubectl get namespaces
KUBECONFIG="$VCLUSTER_KUBECONFIG" kubectl -n secret-sync-vcluster-system get pods
```

Manual smoke test for host namespace -> `vcluster` sync:

```bash
kubectl -n "$SOURCE_NAMESPACE" create secret generic app-db-secret \
  --from-literal=username=appuser \
  --from-literal=password=supersecret

kubectl -n "$SOURCE_NAMESPACE" label secret app-db-secret \
  obegron.github.io/secret-sync-enabled=true

kubectl -n "$SOURCE_NAMESPACE" annotate secret app-db-secret \
  obegron.github.io/secret-sync-targets="[{\"kind\":\"cluster\",\"namespace\":\"$TARGET_NAMESPACE\"}]" \
  obegron.github.io/delete-policy=delete

kubectl -n "$SOURCE_NAMESPACE" get secret app-db-secret
KUBECONFIG="$VCLUSTER_KUBECONFIG" kubectl -n "$TARGET_NAMESPACE" get secret app-db-secret -o yaml
kubectl -n "$SOURCE_NAMESPACE" get events --field-selector involvedObject.name=app-db-secret
```

Useful checks:

```bash
kubectl -n "$VCLUSTER_NAMESPACE" get pods
kubectl -n "$VCLUSTER_NAMESPACE" logs pod/$(kubectl -n "$VCLUSTER_NAMESPACE" get pods -o name | grep secret-sync-controller | head -n1)
KUBECONFIG="$VCLUSTER_KUBECONFIG" kubectl -n "$TARGET_NAMESPACE" get secrets
```

## License

Apache License 2.0. See `LICENSE`.
