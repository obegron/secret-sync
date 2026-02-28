# secret-sync-controller chart

Install:

```bash
helm upgrade --install secret-sync-controller \
  ./charts/secret-sync-controller \
  --namespace secret-sync-system \
  --create-namespace
```

Example values override:

```yaml
image:
  repository: ghcr.io/obegron/secret-sync-controller
  tag: v0.1.0

controller:
  sourceNamespace: tenant-host-ns
  defaultDeletePolicy: delete

kubeconfigSecret:
  name: vcluster-kubeconfigs
  optional: false
```

Render:

```bash
helm template secret-sync-controller \
  ./charts/secret-sync-controller \
  --namespace secret-sync-system
```
