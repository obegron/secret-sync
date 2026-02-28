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
  repository: docker.io/obegron/secret-sync-controller
  tag: "0.1.0" # optional; defaults to chart appVersion

controller:
  sourceNamespace: tenant-host-ns
  defaultDeletePolicy: delete
  tenantSafeMode: true
  allowedSyncTargets: '[{"kind":"vcluster","vcluster":"tenant-a-dev01","namespace":"tenant-host-ns"}]'

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
