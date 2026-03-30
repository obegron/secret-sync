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
  sourceProvider: kubernetes
  kubeconfigSecretName: ""
  kubeconfigSecretKey: config
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

- default: renders `ClusterRole` + `ClusterRoleBinding`
- source mode renders `Role` + `RoleBinding`
- set `rbac.namespaced=true` to force namespaced RBAC for host-side push deployments that only need to read source secrets in their own namespace

Kubeconfig endpoint:

- in `source` mode, the chart can expose `GET /vcluster/v1/kubeconfig`
- set:
  - `controller.kubeconfigSecretName`
  - optionally `controller.kubeconfigSecretKey`
- protect it with:
  - `controller.bridgeTrustIssuers`
  - `controller.bridgeAllowedSubjects`
