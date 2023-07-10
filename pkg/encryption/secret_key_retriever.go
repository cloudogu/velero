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

	corev1 "k8s.io/api/core/v1"
	crlClient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const encryptionKeySecretField = "encryptionKey"

const (
	locationNamespaceKey  = "namespace"
	locationSecretNameKey = "secretName"
)

type secretKeyRetriever struct {
	client     crlClient.Client
	secretName string
	namespace  string
}

func newSecretKeyRetriever(client crlClient.Client, keyLocation velerov1.EncryptionKeyRetrieverConfig) (*secretKeyRetriever, error) {
	secretName := keyLocation[locationSecretNameKey]
	if secretName == "" {
		return nil, fmt.Errorf("secret name cannot be empty")
	}

	namespace := keyLocation[locationNamespaceKey]
	if namespace == "" {
		return nil, fmt.Errorf("namespace cannot be empty")
	}

	return &secretKeyRetriever{client: client, secretName: secretName, namespace: namespace}, nil
}

// RetrieverType designates the source this KeyRetriever fetches the encryption key from.
// In this case, a secret.
func (s *secretKeyRetriever) RetrieverType() velerov1.EncryptionKeyRetrieverType {
	return SecretKeyRetrieverType
}

// Config contains configuration another KeyRetriever of the same type might use to fetch the encryption key.
func (s *secretKeyRetriever) Config() velerov1.EncryptionKeyRetrieverConfig {
	return SecretKeyConfig(s.secretName, s.namespace)
}

// GetKey fetches an encryption key from a Kubernetes secret.
func (s *secretKeyRetriever) GetKey() (string, error) {
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

// SecretKeyConfig creates the retriever config for a key retriever that fetches the encryption key from a secret.
func SecretKeyConfig(secretName, namespace string) velerov1.EncryptionKeyRetrieverConfig {
	return velerov1.EncryptionKeyRetrieverConfig{
		locationSecretNameKey: secretName,
		locationNamespaceKey:  namespace,
	}
}
