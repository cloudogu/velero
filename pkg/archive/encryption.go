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

package archive

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// TODO overall better error messages

// TODO get key from secret
const encryptionKey = "aler,amz3daps.f9hgandkal4dsxk3d0"

func NewDecryptionReader(in io.Reader) (io.Reader, error) {
	// TODO create encryptor according to configuration
	encryptor, err := newAesEncryptor(encryptionKey)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, in)
	if err != nil {
		return nil, err
	}

	ciphertext := buf.Bytes()
	plaintext, err := encryptor.decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(plaintext), nil
}

func NewEncryptionWriter(out io.Writer) (io.WriteCloser, error) {
	// TODO create encryptor according to configuration
	encryptor, err := newAesEncryptor(encryptionKey)
	if err != nil {
		return nil, err
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
		return err
	}

	_, err = ew.out.Write(ciphertext)
	if err != nil {
		return err
	}

	return nil
}

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
		return nil, err
	}

	cipherBytes := aes.gcm.Seal(nonce, nonce, plaintext, nil)
	return cipherBytes, nil
}

func (aes *aesEncryptor) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := aes.gcm.NonceSize()
	nonce, cipherBytesWithoutNounce := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plainBytes, err := aes.gcm.Open(nil, nonce, cipherBytesWithoutNounce, nil)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func newAesEncryptor(key string) (*aesEncryptor, error) {
	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return &aesEncryptor{
		gcm: aesGCM,
		key: keyBytes,
	}, nil
}
