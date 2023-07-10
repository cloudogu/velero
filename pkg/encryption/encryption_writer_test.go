package encryption

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/encryption/mocks"
)

func TestNewEncryptionWriter(t *testing.T) {
	tests := []struct {
		name          string
		encryptionKey string
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
			name:          "should succeed",
			encryptionKey: "abcdefghijklmnopqrstuvwx",
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			got, err := NewEncryptionWriter(out, tt.encryptionKey)

			tt.wantErr(t, err)
			if err == nil {
				require.NotNil(t, got)
				assert.IsType(t, &encryptionWriter{}, got)
			}
		})
	}
}

func Test_encryptionWriter_Write(t *testing.T) {
	tests := []struct {
		name          string
		isClosed      bool
		plaintext     string
		payload       string
		wantPlaintext string
		wantN         int
		wantErr       func(t *testing.T, err error)
	}{
		{
			name:          "should fail if closed",
			isClosed:      true,
			plaintext:     "abc",
			payload:       "def",
			wantPlaintext: "abc",
			wantN:         0,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorContains(t, err, "failed to write: encryption writer is closed")
			},
		},
		{
			name:          "should succeed",
			isClosed:      false,
			plaintext:     "abc",
			payload:       "def",
			wantPlaintext: "abcdef",
			wantN:         3,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ew := &encryptionWriter{
				plaintext: []byte(tt.plaintext),
				isClosed:  tt.isClosed,
			}

			gotN, err := ew.Write([]byte(tt.payload))

			tt.wantErr(t, err)
			assert.Equal(t, tt.wantN, gotN)
			assert.Equal(t, tt.wantPlaintext, string(ew.plaintext))
		})
	}
}

func Test_encryptionWriter_Close(t *testing.T) {
	tests := []struct {
		name        string
		encryptor   encryptor
		out         io.ReadWriter
		isClosed    bool
		wantWritten string
		wantClosed  bool
		wantErr     func(t *testing.T, err error)
	}{
		{
			name:        "should do nothing if closed",
			out:         &bytes.Buffer{},
			isClosed:    true,
			wantWritten: "",
			wantClosed:  true,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name:        "should fail to encrypt",
			encryptor:   failingEncryptor(t),
			out:         &bytes.Buffer{},
			isClosed:    false,
			wantWritten: "",
			wantClosed:  false,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorIs(t, err, assert.AnError)
				assert.ErrorContains(t, err, "failed to encrypt")
			},
		},
		{
			name:        "should fail to write",
			encryptor:   succeedingEncryptor(t),
			out:         &errWriter{},
			isClosed:    false,
			wantWritten: "",
			wantClosed:  true,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorIs(t, err, assert.AnError)
				assert.ErrorContains(t, err, "failed to write cipher text to output writer")
			},
		},
		{
			name:        "should succeed",
			encryptor:   succeedingEncryptor(t),
			out:         &bytes.Buffer{},
			isClosed:    false,
			wantWritten: "encrypted",
			wantClosed:  true,
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ew := &encryptionWriter{
				encryptor: tt.encryptor,
				plaintext: []byte("plaintext"),
				out:       tt.out,
				isClosed:  tt.isClosed,
			}

			err := ew.Close()
			tt.wantErr(t, err)
			assert.Equal(t, tt.wantClosed, ew.isClosed)
			gotOut, err := io.ReadAll(tt.out)
			require.NoError(t, err)
			assert.Equal(t, tt.wantWritten, string(gotOut))
		})
	}
}

func failingEncryptor(t *testing.T) encryptor {
	t.Helper()
	mockEncryptor := mocks.NewEncryptor(t)
	mockEncryptor.EXPECT().Encrypt([]byte("plaintext")).Return(nil, assert.AnError)
	return mockEncryptor
}

func succeedingEncryptor(t *testing.T) encryptor {
	t.Helper()
	mockEncryptor := mocks.NewEncryptor(t)
	mockEncryptor.EXPECT().Encrypt([]byte("plaintext")).Return([]byte("encrypted"), nil)
	return mockEncryptor
}

type errWriter struct{}

func (e *errWriter) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (e *errWriter) Write([]byte) (int, error) {
	return 0, assert.AnError
}
