package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestKeyRetrieverFor(t *testing.T) {
	tests := []struct {
		name          string
		retrieverType v1.EncryptionKeyRetrieverType
		keyLocation   v1.EncryptionKeyRetrieverConfig
		wantRetriever KeyRetriever
		wantErr       func(t *testing.T, err error)
	}{
		{
			name:          "should fail on invalid type",
			retrieverType: v1.EncryptionKeyRetrieverType("invalid"),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "could not create encryption key retriever for type 'invalid': encryption key retriever for type 'invalid' does not exist")
			},
		},
		{
			name:          "should fail to create secret key retriever",
			retrieverType: v1.EncryptionKeyRetrieverType("secret"),
			keyLocation:   SecretKeyConfig("", ""),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "could not create encryption key retriever for type 'secret'")
			},
		},
		{
			name:          "should succeed to create secret key retriever",
			retrieverType: v1.EncryptionKeyRetrieverType("secret"),
			keyLocation:   SecretKeyConfig("mySecret", "myNamespace"),
			wantRetriever: &secretKeyRetriever{
				client:     nil,
				secretName: "mySecret",
				namespace:  "myNamespace",
			},
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRetriever, err := KeyRetrieverFor(tt.retrieverType, tt.keyLocation, nil)
			tt.wantErr(t, err)
			if err == nil {
				assert.Equal(t, tt.wantRetriever, gotRetriever)
			}
		})
	}
}
