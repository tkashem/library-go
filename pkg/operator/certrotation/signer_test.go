package certrotation

import (
	"bytes"
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestSigningCertKeyPairRace(t *testing.T) {
	// represents a secret that was created before 4.7 and
	// hasn't been updated until now (upgrade to 4.15)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "signer", ResourceVersion: "10",
			Annotations: map[string]string{
				"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
				"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
			},
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// give it a second so we have a unique signer name,
	// and also unique not-after, and not-before values
	<-time.After(2 * time.Second)

	// get the original crt and key bytes to compare later
	tlsCertWant, ok := existing.Data["tls.crt"]
	if !ok || len(tlsCertWant) == 0 {
		t.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
	}
	tlsKeyWant, ok := existing.Data["tls.key"]
	if !ok || len(tlsKeyWant) == 0 {
		t.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
	}

	// copy the existing object before test begins, so we can diff it against
	// the final object on the cluster after the controllers finish
	secretWant := existing.DeepCopy()

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := indexer.Add(existing); err != nil {
		t.Fatal(err)
	}
	clientset := kubefake.NewSimpleClientset(existing)

	options := events.RecommendedClusterSingletonCorrelatorOptions()
	recorder1 := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events("ns"), options, "operator", &corev1.ObjectReference{Name: "controller-1", Namespace: "ns"})
	recorder2 := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events("ns"), options, "operator", &corev1.ObjectReference{Name: "controller-2", Namespace: "ns"})

	// waitCh := make(chan struct{})
	// the list cache is synced as soon as we have a delete, create, or update
	clientset.PrependReactor("delete", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		//t.Logf("reactor: %#v", action)
		if err = indexer.Delete(existing); err != nil {
			t.Errorf("unexpected error while syncing the cache, op=delete: %v", err)
		}
		return false, nil, nil
	})
	// after the secret is created, the list cache must be updated
	clientset.PrependReactor("create", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		//t.Logf("reactor: %#v", action)
		switch action := action.(type) {
		case clienttesting.CreateActionImpl:
			indexer.Delete(existing)
			if err := indexer.Add(action.GetObject()); err != nil {
				t.Errorf("unexpected error while syncing the cache, op=create: %v", err)
			}
			return false, action.GetObject(), nil
		}
		t.Errorf("wrong test setup")
		return false, nil, nil
	})
	clientset.PrependReactor("update", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		switch action := action.(type) {
		case clienttesting.UpdateActionImpl:
			indexer.Delete(existing)
			if err := indexer.Add(action.GetObject()); err != nil {
				t.Errorf("unexpected error while syncing the cache, op=update: %v", err)
			}
			return false, action.GetObject(), nil
		}
		t.Errorf("wrong test setup")
		return false, nil, nil
	})

	client := clientset.CoreV1().Secrets("ns")
	client1 := &wrapped{SecretInterface: client, name: "controller-1", t: t}
	getter1 := &getter{w: client1}
	c1 := &RotatedSigningCASecret{
		Namespace:             "ns",
		Name:                  "signer",
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                getter1,
		Lister:                corev1listers.NewSecretLister(indexer),
		AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
		Owner:                 &metav1.OwnerReference{Name: "operator"},
		EventRecorder:         recorder1,
	}
	client2 := &wrapped{SecretInterface: client, name: "controller-2", t: t}
	getter2 := &getter{w: client2}
	c2 := &RotatedSigningCASecret{
		Namespace:             "ns",
		Name:                  "signer",
		Validity:              24 * time.Hour,
		Refresh:               12 * time.Hour,
		Client:                getter2,
		Lister:                corev1listers.NewSecretLister(indexer),
		AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
		Owner:                 &metav1.OwnerReference{Name: "operator"},
		EventRecorder:         recorder2,
	}

	r := rand.New(rand.NewSource(time.Now().Unix()))
	c1DoneCh, c2DoneCh := make(chan *crypto.CA, 1), make(chan *crypto.CA, 1)
	go func() {
		// start the first controller
		// <-time.After(time.Millisecond * time.Duration(r.Intn(2)))
		ca, err := c1.ensureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Logf("error from controller 1 - %v", err)
		}
		c1DoneCh <- ca
	}()
	go func() {
		// start the second controller
		<-time.After(time.Microsecond * time.Duration(r.Intn(100)))
		ca, err := c2.ensureSigningCertKeyPair(context.TODO())
		if err != nil {
			t.Logf("error from controller 2 - %v", err)
		}
		c2DoneCh <- ca
	}()

	<-c1DoneCh
	<-c2DoneCh

	// controllers are done, we don't expect the signer to change
	secretGot, err := clientset.CoreV1().Secrets(c1.Namespace).Get(context.TODO(), c1.Name, metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	if tlsCertGot, ok := secretGot.Data["tls.crt"]; !ok || !bytes.Equal(tlsCertWant, tlsCertGot) {
		t.Errorf("the signer cert has mutated unexpectedly")
	}
	if tlsKeyGot, ok := secretGot.Data["tls.key"]; !ok || !bytes.Equal(tlsKeyWant, tlsKeyGot) {
		t.Errorf("the signer cert has mutated unexpectedly")
	}
	if got, exists := secretGot.Annotations["openshift.io/owning-component"]; !exists || got != "test" {
		t.Errorf("owner annotation is missing: %#v", secretGot.Annotations)
	}

	t.Logf("diff: %s", cmp.Diff(secretWant, secretGot))
}

type getter struct {
	w *wrapped
}

func (g *getter) Secrets(string) corev1client.SecretInterface {
	return g.w
}

type wrapped struct {
	corev1client.SecretInterface
	name string
	t    *testing.T
}

func (w wrapped) Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Create, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Create(ctx, secret, opts)
}
func (w wrapped) Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Update, secret=%s/%s", w.name, secret.Namespace, secret.Name)
	return w.SecretInterface.Update(ctx, secret, opts)
}
func (w wrapped) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	w.t.Logf("[%s] op=Delete, secret=%s", w.name, name)
	return w.SecretInterface.Delete(ctx, name, opts)
}
func (w wrapped) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	w.t.Logf("[%s] op=Get, secret=%s", w.name, name)
	return w.SecretInterface.Get(ctx, name, opts)
}

func TestEnsureSigningCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecret *corev1.Secret

		verifyActions func(t *testing.T, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("create", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
					t.Errorf("expected certificate type 'signer', got: %v", certType)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update no annotations",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer", ResourceVersion: "10"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("update", "secrets") {
					t.Error(actions[1])
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
					t.Errorf("expected certificate type 'signer', got: %v", certType)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update no work",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
						annotations.OpenShiftComponent:             "test",
					}},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "update SecretTLSType secrets",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					}},
				Type: "SecretTypeTLS",
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				actual := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				cert, found := actual.Data["tls.crt"]
				if !found {
					t.Errorf("expected to have tls.crt key")
				}
				if len(cert) != 0 {
					t.Errorf("expected tls.crt to be empty, got %v", cert)
				}
				key, found := actual.Data["tls.key"]
				if !found {
					t.Errorf("expected to have tls.key key")
				}
				if len(key) != 0 {
					t.Errorf("expected tls.key to be empty, got %v", key)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "recreate invalid type secrets",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					}},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foo": {}, "bar": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				actual := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

			client := kubefake.NewSimpleClientset()
			if test.initialSecret != nil {
				indexer.Add(test.initialSecret)
				client = kubefake.NewSimpleClientset(test.initialSecret)
			}

			c := &RotatedSigningCASecret{
				Namespace:     "ns",
				Name:          "signer",
				Validity:      24 * time.Hour,
				Refresh:       12 * time.Hour,
				Client:        client.CoreV1(),
				Lister:        corev1listers.NewSecretLister(indexer),
				EventRecorder: events.NewInMemoryRecorder("test"),
				AdditionalAnnotations: AdditionalAnnotations{
					JiraComponent: "test",
				},
				Owner: &metav1.OwnerReference{
					Name: "operator",
				},
			}

			_, err := c.ensureSigningCertKeyPair(context.TODO())
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyActions(t, client)
		})
	}
}
