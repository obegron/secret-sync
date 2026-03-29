package main

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []syncTarget
		wantErr bool
	}{
		{
			name:  "single target",
			input: `[{"kind":"cluster","namespace":"ns1"}]`,
			want: []syncTarget{
				{Kind: "cluster", Namespace: "ns1"},
			},
		},
		{
			name:  "renamed target",
			input: `[{"kind":"cluster","namespace":"ns1","name":"secret2"}]`,
			want: []syncTarget{
				{Kind: "cluster", Namespace: "ns1", Name: "secret2"},
			},
		},
		{
			name:    "empty namespace",
			input:   `[{"kind":"cluster","namespace":""}]`,
			wantErr: true,
		},
		{
			name:  "duplicate targets deduped",
			input: `[{"kind":"cluster","namespace":"ns1"},{"kind":"cluster","namespace":"ns1"}]`,
			want: []syncTarget{
				{Kind: "cluster", Namespace: "ns1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTargets(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTargets() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseTargets() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSecretChecksum(t *testing.T) {
	secret1 := &corev1.Secret{
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"key": []byte("value")},
	}

	checksum1, err := secretChecksum(secret1)
	if err != nil {
		t.Fatalf("secretChecksum() error = %v", err)
	}

	checksum2, err := secretChecksum(secret1)
	if err != nil {
		t.Fatalf("secretChecksum() second error = %v", err)
	}
	if checksum1 != checksum2 {
		t.Fatal("secretChecksum() not deterministic")
	}

	secret2 := secret1.DeepCopy()
	secret2.Data["key"] = []byte("different")
	checksum3, err := secretChecksum(secret2)
	if err != nil {
		t.Fatalf("secretChecksum() different error = %v", err)
	}
	if checksum1 == checksum3 {
		t.Fatal("secretChecksum() same checksum for different data")
	}
}

func TestEnsureManagedTarget(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				annManagedBy: controllerName,
				annSourceRef: "source-ns/source-secret",
			},
		},
	}

	if err := ensureManagedTarget(secret, "source-ns/source-secret"); err != nil {
		t.Fatalf("ensureManagedTarget() error = %v", err)
	}

	secret.Annotations[annManagedBy] = "other-controller"
	if err := ensureManagedTarget(secret, "source-ns/source-secret"); err == nil {
		t.Fatal("ensureManagedTarget() expected managed-by conflict")
	}
}

func TestReconcileIntoNamespaceCreatesAndUpdates(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}},
	)
	controller := &controller{hostClient: fake.NewSimpleClientset()}
	ctx := context.Background()

	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "source-ns",
			Name:      "source-secret",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key": []byte("value-1"),
		},
	}

	checksum1, err := secretChecksum(src)
	if err != nil {
		t.Fatalf("secretChecksum() error = %v", err)
	}

	if err := controller.reconcileIntoNamespace(ctx, client, src, "target-ns", "target-secret", "cluster/target-ns/target-secret", checksum1); err != nil {
		t.Fatalf("reconcileIntoNamespace() create error = %v", err)
	}

	created, err := client.CoreV1().Secrets("target-ns").Get(ctx, "target-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(created) error = %v", err)
	}
	if string(created.Data["key"]) != "value-1" {
		t.Fatalf("created secret value = %q, want value-1", string(created.Data["key"]))
	}
	if created.Annotations[annSourceRef] != "source-ns/source-secret" {
		t.Fatalf("created source ref = %q", created.Annotations[annSourceRef])
	}

	src.Data["key"] = []byte("value-2")
	checksum2, err := secretChecksum(src)
	if err != nil {
		t.Fatalf("secretChecksum() update error = %v", err)
	}

	if err := controller.reconcileIntoNamespace(ctx, client, src, "target-ns", "target-secret", "cluster/target-ns/target-secret", checksum2); err != nil {
		t.Fatalf("reconcileIntoNamespace() update error = %v", err)
	}

	updated, err := client.CoreV1().Secrets("target-ns").Get(ctx, "target-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(updated) error = %v", err)
	}
	if string(updated.Data["key"]) != "value-2" {
		t.Fatalf("updated secret value = %q, want value-2", string(updated.Data["key"]))
	}
	if updated.Annotations[annChecksum] != checksum2 {
		t.Fatalf("updated checksum = %q, want %q", updated.Annotations[annChecksum], checksum2)
	}
}

func TestReconcileIntoNamespaceImmutableRecreates(t *testing.T) {
	immutable := true
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "target-ns",
				Name:      "target-secret",
				Annotations: map[string]string{
					annManagedBy: controllerName,
					annSourceRef: "source-ns/source-secret",
					annChecksum:  "old-checksum",
				},
			},
			Type:      corev1.SecretTypeOpaque,
			Data:      map[string][]byte{"key": []byte("old")},
			Immutable: &immutable,
		},
	)
	controller := &controller{hostClient: fake.NewSimpleClientset()}
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "source-ns", Name: "source-secret"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"key": []byte("new")},
		Immutable:  &immutable,
	}

	checksum, err := secretChecksum(src)
	if err != nil {
		t.Fatalf("secretChecksum() error = %v", err)
	}
	if err := controller.reconcileIntoNamespace(context.Background(), client, src, "target-ns", "target-secret", "cluster/target-ns/target-secret", checksum); err != nil {
		t.Fatalf("reconcileIntoNamespace() immutable recreate error = %v", err)
	}

	got, err := client.CoreV1().Secrets("target-ns").Get(context.Background(), "target-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got.Data["key"]) != "new" {
		t.Fatalf("recreated secret value = %q, want new", string(got.Data["key"]))
	}
	if got.Annotations[annChecksum] != checksum {
		t.Fatalf("recreated checksum = %q, want %q", got.Annotations[annChecksum], checksum)
	}
}

func TestReconcileIntoNamespaceOwnershipConflict(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "target-ns",
				Name:      "target-secret",
				Annotations: map[string]string{
					annManagedBy: "other-controller",
					annSourceRef: "source-ns/source-secret",
				},
			},
		},
	)
	controller := &controller{hostClient: fake.NewSimpleClientset()}
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "source-ns", Name: "source-secret"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"key": []byte("new")},
	}
	checksum, _ := secretChecksum(src)

	if err := controller.reconcileIntoNamespace(context.Background(), client, src, "target-ns", "target-secret", "cluster/target-ns/target-secret", checksum); err == nil {
		t.Fatal("reconcileIntoNamespace() expected ownership conflict")
	}
}

func TestResolvePullTargetsAndValidatePullTarget(t *testing.T) {
	controller := &controller{
		cfg: runtimeConfig{
			targetNamespace:        "default-target",
			pullNamespaceIsolation: false,
		},
	}
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "source-ns",
			Name:        "source-secret",
			Annotations: map[string]string{},
		},
	}

	targets, err := controller.resolvePullTargets(src)
	if err != nil {
		t.Fatalf("resolvePullTargets() error = %v", err)
	}
	if !reflect.DeepEqual(targets, []syncTarget{{Kind: targetKindCluster, Namespace: "default-target"}}) {
		t.Fatalf("resolvePullTargets() = %#v", targets)
	}

	if err := controller.validatePullTarget(src, syncTarget{Kind: targetKindCluster, Namespace: "source-ns"}); err == nil {
		t.Fatal("validatePullTarget() expected same-cluster source namespace rejection")
	}

	controller.allowedTargetIDs = map[string]struct{}{"cluster/allowed-ns": {}}
	if err := controller.validatePullTarget(src, syncTarget{Kind: targetKindCluster, Namespace: "blocked-ns"}); err == nil {
		t.Fatal("validatePullTarget() expected allowed target rejection")
	}
	if err := controller.validatePullTarget(src, syncTarget{Kind: targetKindCluster, Namespace: "allowed-ns"}); err != nil {
		t.Fatalf("validatePullTarget() allowed target error = %v", err)
	}
}

func TestHandleDeletePullPolicies(t *testing.T) {
	ctrl := &controller{
		localClient: fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "target-ns",
					Name:      "source-secret",
					Annotations: map[string]string{
						annManagedBy: controllerName,
						annSourceRef: "source-ns/source-secret",
					},
				},
			},
		),
		hostClient: fake.NewSimpleClientset(),
		cfg: runtimeConfig{
			targetNamespace:     "target-ns",
			defaultDeletePolicy: "delete",
		},
	}

	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "source-ns",
			Name:      "source-secret",
			Labels:    map[string]string{labelSyncEnabled: "true"},
		},
	}

	if err := ctrl.handleDeletePull(context.Background(), src); err != nil {
		t.Fatalf("handleDeletePull() delete error = %v", err)
	}
	if _, err := ctrl.localClient.CoreV1().Secrets("target-ns").Get(context.Background(), "source-secret", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Get(deleted secret) error = %v, want not found", err)
	}

	retainController := &controller{
		localClient: fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "target-ns",
					Name:      "source-secret",
					Annotations: map[string]string{
						annManagedBy: controllerName,
						annSourceRef: "source-ns/source-secret",
					},
				},
			},
		),
		hostClient: fake.NewSimpleClientset(),
		cfg: runtimeConfig{
			targetNamespace:     "target-ns",
			defaultDeletePolicy: "delete",
		},
	}
	retainSrc := src.DeepCopy()
	retainSrc.Annotations = map[string]string{annDeletePolicy: "retain"}
	if err := retainController.handleDeletePull(context.Background(), retainSrc); err != nil {
		t.Fatalf("handleDeletePull() retain error = %v", err)
	}
	if _, err := retainController.localClient.CoreV1().Secrets("target-ns").Get(context.Background(), "source-secret", metav1.GetOptions{}); err != nil {
		t.Fatalf("Get(retained secret) error = %v", err)
	}
}

func TestParseAllowedTargetIDs(t *testing.T) {
	got, err := parseAllowedTargetIDs(`[{"kind":"cluster","namespace":"ns1"},{"kind":"cluster","namespace":"ns2","name":"secret2"}]`)
	if err != nil {
		t.Fatalf("parseAllowedTargetIDs() error = %v", err)
	}
	want := map[string]struct{}{
		"cluster/ns1":         {},
		"cluster/ns2/secret2": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseAllowedTargetIDs() = %#v, want %#v", got, want)
	}

	if _, err := parseAllowedTargetIDs(`not-json`); err == nil {
		t.Fatal("parseAllowedTargetIDs() expected parse error")
	}
}

func TestReconcileIgnoresSecretWithoutEnabledLabel(t *testing.T) {
	ctrl := &controller{hostClient: fake.NewSimpleClientset()}
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "source-ns",
			Name:      "source-secret",
			Labels:    map[string]string{labelSyncEnabled: "yes"},
			Annotations: map[string]string{
				annSyncTargets: `[{"kind":"cluster","namespace":"target-ns"}]`,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"key": []byte("value")},
	}

	if err := ctrl.reconcile(context.Background(), src); err != nil {
		t.Fatalf("reconcile() error = %v, want nil", err)
	}
	if got := ctrl.metrics.reconcileTotal.Load(); got != 0 {
		t.Fatalf("reconcileTotal = %d, want 0", got)
	}
}

func TestHandleDeletePullInvalidDeletePolicyFallsBackToDefault(t *testing.T) {
	ctrl := &controller{
		localClient: fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "target-ns",
					Name:      "source-secret",
					Annotations: map[string]string{
						annManagedBy: controllerName,
						annSourceRef: "source-ns/source-secret",
					},
				},
			},
		),
		hostClient: fake.NewSimpleClientset(),
		cfg: runtimeConfig{
			targetNamespace:     "target-ns",
			defaultDeletePolicy: "retain",
		},
	}

	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "source-ns",
			Name:      "source-secret",
			Labels:    map[string]string{labelSyncEnabled: "true"},
			Annotations: map[string]string{
				annDeletePolicy: "invalid-policy",
			},
		},
	}

	if err := ctrl.handleDeletePull(context.Background(), src); err != nil {
		t.Fatalf("handleDeletePull() error = %v", err)
	}
	if _, err := ctrl.localClient.CoreV1().Secrets("target-ns").Get(context.Background(), "source-secret", metav1.GetOptions{}); err != nil {
		t.Fatalf("Get(retained secret) error = %v", err)
	}
}

func TestReconcileInvalidTargetsFail(t *testing.T) {
	ctrl := &controller{hostClient: fake.NewSimpleClientset()}
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "source-ns",
			Name:      "source-secret",
			Labels:    map[string]string{labelSyncEnabled: "true"},
			Annotations: map[string]string{
				annSyncTargets: `not-json`,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"key": []byte("value")},
	}

	if err := ctrl.reconcile(context.Background(), src); err == nil {
		t.Fatal("reconcile() expected invalid target error")
	}
	if got := ctrl.metrics.reconcileTotal.Load(); got != 1 {
		t.Fatalf("reconcileTotal = %d, want 1", got)
	}
}
