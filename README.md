# secret-sync-controller

Annotation-driven controller that syncs selected host-cluster Secrets to one or many targets.

Supported target kinds:

- `vcluster`
- `cluster`

## Source Secret contract

Required label:

- `obegron.github.io/secret-sync-enabled=true`

Required annotation:

- `obegron.github.io/secret-sync-targets` (JSON array)

Example target annotation value:

```json
[
  {"kind":"vcluster","vcluster":"tenant-a-dev01","namespace":"app-runtime"},
  {"kind":"cluster","namespace":"shared-runtime"}
]
```

Optional annotation:

- `obegron.github.io/delete-policy=delete|retain` (default from `DEFAULT_DELETE_POLICY`)

## Runtime configuration

- `HOST_KUBECONFIG` (optional; if unset, use in-cluster config)
- `SOURCE_NAMESPACE` (optional; if unset, watch all namespaces)
- `VCLUSTER_KUBECONFIG_DIR` (default `/etc/vcluster-kubeconfigs`)
- `DEFAULT_DELETE_POLICY` (`delete` or `retain`, default `delete`)
- `METRICS_BIND_ADDRESS` (default `:8080`; serves `/healthz`, `/readyz`, `/metrics`)

Vcluster kubeconfig files are resolved as:

- `/etc/vcluster-kubeconfigs/<vcluster-name>.kubeconfig`

## Sync behavior

- Copies secret `type`, `data`, and `immutable`.
- Target secret name is same as source name.
- Adds managed annotations:
  - `obegron.github.io/managed-by=secret-sync-controller`
  - `obegron.github.io/source=<source-namespace>/<source-name>`
  - `obegron.github.io/checksum=<sha256>`
- Updates only when checksum changes.
- If target secret is immutable and content changes, controller recreates it.
- On source delete, controller deletes targets unless delete policy is `retain`.

## Local integration test

Required commands:

- `docker`
- `k3d`
- `kubectl`
- `helm`
- `curl`

Run full flow:

```bash
make integration-test
```

Teardown:

```bash
make integration-down
```

Defaults use:

- k3d cluster: `secret-sync-it`
- vcluster release: `tenant-a-dev01` in namespace `vcluster-tenant-a-dev01`
- source secret: `tenant-host-ns/app-db-secret`
- vcluster target namespace: `app-runtime`
- cluster target namespaces: `shared-runtime`, `shared-runtime-2`

## License

Apache License 2.0. See `LICENSE`.

## Deploy

Kustomize manifests:

```bash
kubectl apply -k deploy/base
```

Helm chart:

```bash
helm upgrade --install secret-sync-controller \
  ./charts/secret-sync-controller \
  --namespace secret-sync-system \
  --create-namespace
```

## After Install

Create required namespaces:

```bash
kubectl create namespace tenant-host-ns --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace shared-runtime --dry-run=client -o yaml | kubectl apply -f -
```

Create the target namespace inside your vcluster:

```bash
KUBECONFIG=/path/to/tenant-a-dev01.kubeconfig \
  kubectl create namespace app-runtime --dry-run=client -o yaml | \
  KUBECONFIG=/path/to/tenant-a-dev01.kubeconfig kubectl apply -f -
```

For the many-target-namespaces example, also create:

```bash
kubectl create namespace shared-runtime-a --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace shared-runtime-b --dry-run=client -o yaml | kubectl apply -f -
KUBECONFIG=/path/to/tenant-a-dev01.kubeconfig \
  kubectl create namespace app-runtime-a --dry-run=client -o yaml | \
  KUBECONFIG=/path/to/tenant-a-dev01.kubeconfig kubectl apply -f -
KUBECONFIG=/path/to/tenant-a-dev01.kubeconfig \
  kubectl create namespace app-runtime-b --dry-run=client -o yaml | \
  KUBECONFIG=/path/to/tenant-a-dev01.kubeconfig kubectl apply -f -
```

Apply vcluster kubeconfig secret (controller reads vcluster kubeconfigs from this Secret):

```bash
kubectl apply -f deploy/examples/vcluster-kubeconfigs-secret.yaml
```

Apply a source Secret with multi-target sync (vcluster + host cluster):

```bash
kubectl apply -f deploy/examples/source-secret.yaml
```

Apply a source Secret with vcluster-only sync:

```bash
kubectl apply -f deploy/examples/source-secret-vcluster-only.yaml
```

Apply a source Secret with host-cluster-only sync:

```bash
kubectl apply -f deploy/examples/source-secret-cluster-only.yaml
```

Apply a source Secret with many target namespaces:

```bash
kubectl apply -f deploy/examples/source-secret-many-namespaces.yaml
```

Example manifests are in:

- `deploy/examples/vcluster-kubeconfigs-secret.yaml`
- `deploy/examples/source-secret.yaml`
- `deploy/examples/source-secret-vcluster-only.yaml`
- `deploy/examples/source-secret-cluster-only.yaml`
- `deploy/examples/source-secret-many-namespaces.yaml`
