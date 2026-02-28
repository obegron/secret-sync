# vcluster-secret-sync-controller chart

Install:

```bash
helm upgrade --install vcluster-secret-sync-controller \
  /home/egron/source/secret-sync/charts/vcluster-secret-sync-controller \
  --namespace vcluster-secret-sync-system \
  --create-namespace
```

Example values override:

```yaml
image:
  repository: ghcr.io/obegron/vcluster-secret-sync-controller
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
helm template vcluster-secret-sync-controller \
  /home/egron/source/secret-sync/charts/vcluster-secret-sync-controller \
  --namespace vcluster-secret-sync-system
```
