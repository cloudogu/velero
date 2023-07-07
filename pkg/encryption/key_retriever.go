package encryption

import (
	"fmt"

	crlClient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// SecretKeyRetrieverType designates a KeyRetriever that fetches the encryption key from a Kubernetes secret.
const SecretKeyRetrieverType velerov1.EncryptionKeyRetrieverType = "secret"

// KeyRetriever is used to fetch an encryption key.
type KeyRetriever interface {
	// GetKey fetches an encryption key.
	GetKey() (string, error)
	// RetrieverType designates the source this KeyRetriever fetches the encryption key from.
	RetrieverType() velerov1.EncryptionKeyRetrieverType
	// Config contains configuration another KeyRetriever of the same type might use to fetch the encryption key.
	Config() velerov1.EncryptionKeyRetrieverConfig
}

// KeyRetrieverFor creates a KeyRetriever of the given type according to the given configuration.
func KeyRetrieverFor(retrieverType velerov1.EncryptionKeyRetrieverType, keyLocation velerov1.EncryptionKeyRetrieverConfig, client crlClient.Client) (retriever KeyRetriever, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("could not create encryption key retriever for type '%s': %w", retrieverType, err)
		}
	}()

	switch retrieverType {
	case SecretKeyRetrieverType:
		return newSecretKeyRetriever(client, keyLocation)
	default:
		return nil, fmt.Errorf("could not find encryption key retriever for type '%s'", retrieverType)
	}
}
