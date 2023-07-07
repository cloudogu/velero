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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type encryptor interface {
	encrypt(plaintext []byte) ([]byte, error)
	decrypt(ciphertext []byte) ([]byte, error)
}

type aesEncryptor struct {
	gcm cipher.AEAD
	key []byte
}

func (aes *aesEncryptor) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aes.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to create nonce for encryption: %w", err)
	}

	cipherBytes := aes.gcm.Seal(nonce, nonce, plaintext, nil)
	return cipherBytes, nil
}

func (aes *aesEncryptor) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := aes.gcm.NonceSize()
	if len(ciphertext) <= nonceSize {
		return nil, fmt.Errorf("failed to decrypt: ciphertext (length %d) too short", len(ciphertext))
	}

	nonce, cipherBytesWithoutNonce := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plainBytes, err := aes.gcm.Open(nil, nonce, cipherBytesWithoutNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plainBytes, nil
}

func newAesEncryptor(key string) (*aesEncryptor, error) {
	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create Galois Counter Mode for cipher: %w", err)
	}

	return &aesEncryptor{
		gcm: aesGCM,
		key: keyBytes,
	}, nil
}
