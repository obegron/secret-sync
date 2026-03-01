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
  syncMode: push
  sourceNamespace: tenant-host-ns
  defaultDeletePolicy: delete
  tenantSafeMode: false
  allowedSyncTargets: '[{"kind":"cluster","namespace":"shared-runtime"}]'
```

Render:

```bash
helm template secret-sync-controller \
  ./charts/secret-sync-controller \
  --namespace secret-sync-system
```
