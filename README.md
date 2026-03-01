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
  {"kind":"cluster","namespace":"shared-runtime"}
]
```

Optional annotation:

- `obegron.github.io/delete-policy=delete|retain` (default from `DEFAULT_DELETE_POLICY`)

## Runtime configuration

- `SYNC_MODE` (`push` or `pull`, default `push`)
- `HOST_KUBECONFIG` (optional)
- `POD_NAMESPACE` (set by Downward API in manifests/chart)
- `SOURCE_NAMESPACE`
- `TARGET_NAMESPACE` (used by `pull` mode; if unset, defaults to `POD_NAMESPACE`)
- `HOST_API_SERVER` (used by `pull` mode when `HOST_KUBECONFIG` is not set)
- `HOST_TOKEN_FILE` (used by `pull` mode, default serviceaccount token path)
- `HOST_CA_FILE` (used by `pull` mode, default serviceaccount CA path)
- `DEFAULT_DELETE_POLICY` (`delete` or `retain`, default `delete`)
- `TENANT_SAFE_MODE` (`true|false`, default `false`; pull mode only)
- `ALLOWED_SYNC_TARGETS` (optional JSON array allowlist, push mode)
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
- `pull`: watches source Secrets and mirrors to one local namespace; `secret-sync-targets` is ignored

## Security modes

Tenant-safe mode (`TENANT_SAFE_MODE=true`):

- intended for pull mode
- scopes source to pod namespace when `SOURCE_NAMESPACE` is unset

Platform mode (`TENANT_SAFE_MODE=false`):

- set `SOURCE_NAMESPACE` and/or `ALLOWED_SYNC_TARGETS` to constrain blast radius

## Build and release

```bash
make show-version
make set-version VERSION=0.1.1
make docker-build
make docker-push
```

`set-version` updates:

- `VERSION`
- `charts/secret-sync-controller/Chart.yaml` `version`
- `charts/secret-sync-controller/Chart.yaml` `appVersion`

Run container vulnerability scan:

```bash
make scan-image
```

## Local integration test

```bash
make integration-test
make integration-test-pull
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

## OIDC helper (for vcluster pull auth)

`cmd/oidc-helper` provides an OIDC discovery/JWKS endpoint in two modes:

- `OIDC_MODE=proxy`: proxies Kubernetes `/.well-known/openid-configuration` and `/openid/v1/jwks`, rewriting `jwks_uri` to `ENVIRONMENT_BASE_URL`.
- `OIDC_MODE=static`: serves static OIDC config/JWKS from file or inline JSON (useful for integration tests without live upstream).

Build/run:

```bash
make build-oidc-helper
make run-oidc-helper
```

## License

Apache License 2.0. See `LICENSE`.
