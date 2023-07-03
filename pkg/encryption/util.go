package encryption

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	crlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

const encryptionKeySecretField = "encryptionKey"

func getEncryptionKeyFromSecret(client crlClient.Client, secretName string, namespace string) (string, error) {
	secret := v1.Secret{}
	err := client.Get(context.Background(), crlClient.ObjectKey{Name: secretName, Namespace: namespace}, &secret)
	if err != nil {
		return "", fmt.Errorf("failed to get encryption key secret '%s': %w", secretName, err)
	}

	key, ok := secret.Data[encryptionKeySecretField]
	if !ok {
		return "", fmt.Errorf("encryption key secret '%s' lacks field '%s'", secretName, encryptionKeySecretField)
	}

	return string(key), nil
}
