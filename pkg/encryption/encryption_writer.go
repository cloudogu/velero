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
	"fmt"
	"io"
)

// NewEncryptionWriter provides a writer that encrypts whatever is written with the given key and writes it into the given writer.
func NewEncryptionWriter(out io.Writer, encryptionKey string) (io.WriteCloser, error) {
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
	isClosed  bool
}

func (ew *encryptionWriter) Write(p []byte) (n int, err error) {
	if ew.isClosed {
		return 0, fmt.Errorf("failed to write: encryption writer is closed")
	}

	ew.plaintext = append(ew.plaintext, p...)
	return len(p), nil
}

func (ew *encryptionWriter) Close() error {
	if ew.isClosed {
		return nil
	}

	ciphertext, err := ew.encryptor.Encrypt(ew.plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	ew.isClosed = true

	_, err = ew.out.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write cipher text to output writer: %w", err)
	}

	return nil
}
