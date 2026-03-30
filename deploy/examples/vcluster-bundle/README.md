# Bundled vcluster bridge example

This example shows one way to bundle:

- the rendered host-side `vcluster` install
- the outer host-side `secret-sync-source`
- the inner `secret-sync-controller` deployed by `vcluster` via `experimental.deploy.vcluster.helm`

The top-level apply is:

```bash
kustomize build --enable-helm deploy/examples/vcluster-bundle | kubectl apply -f -
```

Before that, prepare the `vcluster` render:

1. Package the local `secret-sync-controller` chart into a `.tgz` and convert it to base64.
2. Replace `REPLACE_WITH_SECRET_SYNC_CONTROLLER_CHART_BUNDLE` in [vcluster-values.yaml](./vcluster-values.yaml).
3. Render the `vcluster` chart with those values into [rendered-vcluster/vcluster-rendered.yaml](./rendered-vcluster/vcluster-rendered.yaml).

Example render flow:

```bash
helm template secret-sync-vcluster vcluster \
  --repo https://charts.loft.sh \
  --namespace secret-sync-vcluster \
  --values deploy/examples/vcluster-bundle/vcluster-values.yaml \
  > deploy/examples/vcluster-bundle/rendered-vcluster/vcluster-rendered.yaml
```

What this example installs:

- host namespace `secret-sync-vcluster`
- rendered `vcluster` host resources
- outer `secret-sync-source` via Kustomize Helm support
- inner `secret-sync-controller` via `experimental.deploy.vcluster.helm`

Ingress hosts used in this example:

- outer bridge/source endpoint: `secret-sync-source.example.test`
- inner OIDC endpoint: `secret-sync-controller.example.test`

Notes:

- `experimental.deploy` is still an experimental `vcluster` feature. Use pinned `vcluster` versions and test upgrades before rollout.
- The inner chart bundle is embedded into the `vcluster` config so this example can stay self-contained.
- Adjust the inner `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT` values if your `vcluster` service naming differs.
