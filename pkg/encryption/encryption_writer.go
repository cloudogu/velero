package encryption

import (
	"fmt"
	"io"

	crlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

func NewEncryptionWriter(out io.Writer, client crlClient.Client, secretName string) (io.WriteCloser, error) {
	encryptionKey, err := getEncryptionKeyFromSecret(client, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key from secret: %w", err)
	}

	encryptor, err := newAesEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES encryptor: %w", err)
	}

	return &encryptionWriter{
		encryptor: encryptor,
		plaintext: make([]byte, 0),
		out:       out,
	}, nil
}

type encryptionWriter struct {
	encryptor encryptor
	plaintext []byte
	out       io.Writer
}

func (ew *encryptionWriter) Write(p []byte) (n int, err error) {
	ew.plaintext = append(ew.plaintext, p...)
	return len(p), nil
}

func (ew *encryptionWriter) Close() error {
	ciphertext, err := ew.encryptor.encrypt(ew.plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	_, err = ew.out.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write cipher text to output writer: %w", err)
	}

	return nil
}
