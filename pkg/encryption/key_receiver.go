package encryption

import (
	"fmt"

	crlClient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const SecretKeyReceiverType velerov1.EncryptionKeyReceiverType = "secret"

type KeyReceiver interface {
	GetKey() (string, error)
	ReceiverType() velerov1.EncryptionKeyReceiverType
	KeyLocation() velerov1.EncryptionKeyLocation
}

func KeyReceiverFor(receiverType velerov1.EncryptionKeyReceiverType, keyLocation velerov1.EncryptionKeyLocation, client crlClient.Client) (receiver KeyReceiver, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("could not create encryption key receiver for type '%s': %w", receiverType, err)
		}
	}()

	switch receiverType {
	case SecretKeyReceiverType:
		return newSecretKeyReceiver(client, keyLocation)
	default:
		return nil, fmt.Errorf("could not find encryption key receiver for type '%s'", receiverType)
	}
}
