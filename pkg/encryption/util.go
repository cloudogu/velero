package encryption

import (
	"context"
	"encoding/base64"
	"fmt"

	v1 "k8s.io/api/core/v1"
	crlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

const encryptionKeySecretField = "encryptionKey"

func getEncryptionKeyFromSecret(client crlClient.Client, secretName string) (string, error) {
	secret := v1.Secret{}
	// TODO how to get namespace? is it even needed here?
	err := client.Get(context.Background(), crlClient.ObjectKey{Name: secretName}, &secret)
	if err != nil {
		return "", fmt.Errorf("failed to get encryption key secret '%s': %w", secretName, err)
	}

	encodedKey, ok := secret.Data[encryptionKeySecretField]
	if !ok {
		return "", fmt.Errorf("encryption key secret '%s' lacks field '%s'", secretName, encryptionKeySecretField)
	}

	var decodeBuffer []byte
	_, err = base64.StdEncoding.Decode(decodeBuffer, encodedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encryption key secret '%s': %w", secretName, err)
	}

	return string(decodeBuffer), nil
}
