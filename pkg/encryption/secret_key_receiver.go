package encryption

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	crlClient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const encryptionKeySecretField = "encryptionKey"

const (
	locationNamespaceKey  = "namespace"
	locationSecretNameKey = "secretName"
)

type secretKeyReceiver struct {
	client     crlClient.Client
	secretName string
	namespace  string
}

func newSecretKeyReceiver(client crlClient.Client, keyLocation velerov1.EncryptionKeyLocation) (*secretKeyReceiver, error) {
	secretName := keyLocation[locationSecretNameKey]
	if secretName == "" {
		return nil, fmt.Errorf("secret name cannot be empty")
	}

	namespace := keyLocation[locationNamespaceKey]
	if namespace == "" {
		return nil, fmt.Errorf("namespace cannot be empty")
	}

	return &secretKeyReceiver{client: client, secretName: secretName, namespace: namespace}, nil
}

func (s *secretKeyReceiver) ReceiverType() velerov1.EncryptionKeyReceiverType {
	return SecretKeyReceiverType
}

func (s *secretKeyReceiver) KeyLocation() velerov1.EncryptionKeyLocation {
	return SecretKeyLocation(s.secretName, s.namespace)
}

func (s *secretKeyReceiver) GetKey() (string, error) {
	secret := corev1.Secret{}
	err := s.client.Get(context.Background(), crlClient.ObjectKey{Name: s.secretName, Namespace: s.namespace}, &secret)
	if err != nil {
		return "", fmt.Errorf("failed to get encryption key secret '%s': %w", s.secretName, err)
	}

	key, ok := secret.Data[encryptionKeySecretField]
	if !ok {
		return "", fmt.Errorf("encryption key secret '%s' lacks field '%s'", s.secretName, encryptionKeySecretField)
	}

	return string(key), nil
}

func SecretKeyLocation(secretName, namespace string) velerov1.EncryptionKeyLocation {
	return velerov1.EncryptionKeyLocation{
		locationSecretNameKey: secretName,
		locationNamespaceKey:  namespace,
	}
}
