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
	"bytes"
	"fmt"
	"io"
)

// NewDecryptionReader provides a reader that decrypts the contents of the given reader with the given key.
func NewDecryptionReader(in io.Reader, encryptionKey string) (io.Reader, error) {
	encryptor, err := newAesEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES encryptor: %w", err)
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, in)
	if err != nil {
		return nil, fmt.Errorf("failed to copy input to buffer: %w", err)
	}

	ciphertext := buf.Bytes()
	plaintext, err := encryptor.decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(plaintext), nil
}