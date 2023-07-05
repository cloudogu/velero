/*
Copyright 2023 the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package encryption

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	crlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

const encryptionKeySecretField = "encryptionKey"

// GetEncryptionKeyFromSecret fetches the secret with the given name in the given namespace.
func GetEncryptionKeyFromSecret(client crlClient.Client, secretName string, namespace string) (string, error) {
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
