# vcluster-secret-sync-controller

Annotation-driven controller that syncs selected host-cluster Secrets into target vclusters.

## Source Secret contract

Required label:

- `obegron.github.io/sync-to-vcluster=true`

Required annotations:

- `obegron.github.io/vcluster-name=tenant-a-dev01`
- `obegron.github.io/vcluster-namespace=app-runtime`

Optional annotation:

- `obegron.github.io/delete-policy=delete|retain` (default from `DEFAULT_DELETE_POLICY`)

## Runtime configuration

- `HOST_KUBECONFIG` (optional; if unset, use in-cluster config)
- `SOURCE_NAMESPACE` (optional; if unset, watch all namespaces)
- `VCLUSTER_KUBECONFIG_DIR` (default `/etc/vcluster-kubeconfigs`)
- `DEFAULT_DELETE_POLICY` (`delete` or `retain`, default `delete`)
- `METRICS_BIND_ADDRESS` (default `:8080`; serves `/healthz`, `/readyz`, `/metrics`)

Vcluster kubeconfig files are resolved as:

- `/etc/vcluster-kubeconfigs/tenant-a-dev01.kubeconfig`

## Sync behavior

- Copies secret `type`, `data`, and `immutable`.
- Target secret name is same as source name.
- Adds managed annotations:
  - `obegron.github.io/managed-by=vcluster-secret-sync-controller`
  - `obegron.github.io/source=tenant-host-ns/app-db-secret`
  - `obegron.github.io/checksum=<sha256>`
- Updates only when checksum changes.
- If target secret is immutable and content changes, controller recreates it.
- On source delete, controller deletes target unless delete policy is `retain`.

## Local integration test

Required commands:

- `docker`
- `k3d`
- `kubectl`
- `helm`

Run full flow (cluster + kustomize-installed vcluster + controller + synced secret validation):

```bash
make integration-test
```

Teardown:

```bash
make integration-down
```

Defaults use:

- k3d cluster: `vcluster-secret-sync-it`
- vcluster release: `tenant-a-dev01` in namespace `vcluster-tenant-a-dev01`
- source secret: `tenant-host-ns/app-db-secret`
- target namespace in vcluster: `app-runtime`

Override any value with Make variables, for example:

```bash
make integration-test VCLUSTER_NAME=tenant-b-test02 TARGET_NAMESPACE=runtime
```

The vcluster install is rendered from [deploy/integration/vcluster/kustomization.yaml.tmpl](/home/egron/source/secret-sync/deploy/integration/vcluster/kustomization.yaml.tmpl) using Kustomize Helm support, matching a GitOps-style manifest workflow.

## License

Apache License 2.0. See `LICENSE`.

## Deploy

See manifests in `deploy/`.
