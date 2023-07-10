package encryption

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
	"testing/iotest"
)

func TestNewDecryptionReader(t *testing.T) {
	tests := []struct {
		name          string
		in            io.Reader
		encryptionKey string
		want          []byte
		wantErr       func(t *testing.T, err error)
	}{
		{
			name:          "should fail to create encryptor",
			encryptionKey: "invalid",
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "failed to create AES encryptor")
			},
		},
		{
			name:          "should fail to copy from reader",
			in:            iotest.ErrReader(assert.AnError),
			encryptionKey: "abcdefghijklmnopqrstuvwx",
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorIs(t, err, assert.AnError)
				assert.ErrorContains(t, err, "failed to copy input to buffer")
			},
		},
		{
			name:          "should fail to decrypt",
			in:            bytes.NewReader([]byte("invalid")),
			encryptionKey: "abcdefghijklmnopqrstuvwx",
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "failed to decrypt: ciphertext (length 7) too short")
			},
		},
		{
			name:          "should succeed",
			in:            bytes.NewReader([]byte("}vt9!\xe1-M\x12\xa2\x82\x10\xde<\xab\xbb\x05\f\x89\xdeÖ\xcd\xf6\bU\x11\x99֎\x05\xf0B\xce\xea$R")),
			encryptionKey: "abcdefghijklmnopqrstuvwx",
			want:          []byte("plaintext"),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecryptionReader(tt.in, tt.encryptionKey)

			tt.wantErr(t, err)
			if err == nil {
				actual, err := io.ReadAll(got)
				require.NoError(t, err)
				assert.Equal(t, string(tt.want), string(actual))
			}
		})
	}
}
