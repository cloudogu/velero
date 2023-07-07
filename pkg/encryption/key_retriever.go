package encryption

import (
	"fmt"

	crlClient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const SecretKeyRetrieverType velerov1.EncryptionKeyRetrieverType = "secret"

type KeyRetriever interface {
	GetKey() (string, error)
	RetrieverType() velerov1.EncryptionKeyRetrieverType
	KeyLocation() velerov1.EncryptionKeyLocation
}

func KeyRetrieverFor(retrieverType velerov1.EncryptionKeyRetrieverType, keyLocation velerov1.EncryptionKeyLocation, client crlClient.Client) (retriever KeyRetriever, err error) {
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
