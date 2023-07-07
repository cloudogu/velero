package encryption

import (
	"crypto/rand"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newAesEncryptor(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		notEmpty bool
		wantErr  func(t *testing.T, err error)
	}{
		{
			name: "should fail to create cipher",
			key:  "invalid",
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "failed to create AES cipher: crypto/aes: invalid key size 7")
			},
		},
		{
			name:     "should succeed",
			key:      "abcdefghijklmnopqrstuvwx",
			notEmpty: true,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newAesEncryptor(tt.key)

			tt.wantErr(t, err)
			if tt.notEmpty {
				assert.NotEmpty(t, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func Test_aesEncryptor_encrypt(t *testing.T) {
	t.Run("should fail to create nonce", func(t *testing.T) {
		// given
		originalRandReader := rand.Reader
		defer func() { rand.Reader = originalRandReader }()
		rand.Reader = iotest.ErrReader(assert.AnError)

		aes, err := newAesEncryptor("abcdefghijklmnopqrstuvwx")
		require.NoError(t, err)

		// when
		got, err := aes.encrypt([]byte("plaintext"))

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
		assert.ErrorContains(t, err, "failed to create nonce for encryption")
		assert.Nil(t, got)
	})
	t.Run("should succeed", func(t *testing.T) {
		// given
		aes, err := newAesEncryptor("abcdefghijklmnopqrstuvwx")
		require.NoError(t, err)

		// when
		got, err := aes.encrypt([]byte("plaintext"))

		// then
		require.NoError(t, err)
		assert.NotEmpty(t, got)
		decrypted, err := aes.decrypt(got)
		assert.Equal(t, "plaintext", string(decrypted))
	})
}

func Test_aesEncryptor_decrypt(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext []byte
		want       []byte
		wantErr    func(t *testing.T, err error)
	}{
		{
			name:       "should fail on too short text",
			ciphertext: []byte("short"),
			want:       nil,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "failed to decrypt: ciphertext (length 5) too short")
			},
		},
		{
			name:       "should fail on invalid text",
			ciphertext: []byte("invalid-ciphertext"),
			want:       nil,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "failed to decrypt ciphertext: cipher: message authentication failed")
			},
		},
		{
			name:       "should succeed",
			ciphertext: []byte("}vt9!\xe1-M\x12\xa2\x82\x10\xde<\xab\xbb\x05\f\x89\xdeÖ\xcd\xf6\bU\x11\x99֎\x05\xf0B\xce\xea$R"),
			want:       []byte("plaintext"),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aes, err := newAesEncryptor("abcdefghijklmnopqrstuvwx")
			require.NoError(t, err)

			got, err := aes.decrypt(tt.ciphertext)
			tt.wantErr(t, err)
			assert.Equalf(t, string(tt.want), string(got), "decrypt(%v)", tt.ciphertext)
		})
	}
}
