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
  tag: "0.2.0" # optional; defaults to chart appVersion

controller:
  syncMode: push
  hostKubeconfig: ""
  sourceNamespace: tenant-host-ns
  defaultDeletePolicy: delete
  pullNamespaceIsolation: false
  allowedSyncTargets: '[{"kind":"cluster","namespace":"shared-runtime"}]'

extraEnv: []
extraVolumes: []
extraVolumeMounts: []
```

Render:

```bash
helm template secret-sync-controller \
  ./charts/secret-sync-controller \
  --namespace secret-sync-system
```

RBAC behavior:

- the chart renders `ClusterRole` + `ClusterRoleBinding`
- this is required for push mode and for pull mode when targets are outside the controller release namespace
