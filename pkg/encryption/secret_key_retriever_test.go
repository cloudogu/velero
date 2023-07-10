package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
)

func Test_newSecretKeyRetriever(t *testing.T) {
	tests := []struct {
		name        string
		keyLocation v1.EncryptionKeyRetrieverConfig
		want        *secretKeyRetriever
		wantErr     func(t *testing.T, err error)
	}{
		{
			name:        "should fail if secret name is empty",
			keyLocation: SecretKeyConfig("", "myNamespace"),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "secret name cannot be empty")
			},
		},
		{
			name:        "should fail if namespace is empty",
			keyLocation: SecretKeyConfig("mySecret", ""),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "namespace cannot be empty")
			},
		},
		{
			name:        "should succeed",
			keyLocation: SecretKeyConfig("mySecret", "myNamespace"),
			want: &secretKeyRetriever{
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
			got, err := newSecretKeyRetriever(nil, tt.keyLocation)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_secretKeyRetriever_RetrieverType(t *testing.T) {
	t.Run("should return secret retriever type", func(t *testing.T) {
		// given
		sut := &secretKeyRetriever{}

		// when
		actual := sut.RetrieverType()

		// then
		assert.Equal(t, v1.EncryptionKeyRetrieverType("secret"), actual)
	})
}

func Test_secretKeyRetriever_Config(t *testing.T) {
	tests := []struct {
		name       string
		secretName string
		namespace  string
		want       v1.EncryptionKeyRetrieverConfig
	}{
		{
			name:       "should return config for name 'mySecret' and namespace 'myNamespace'",
			secretName: "mySecret",
			namespace:  "myNamespace",
			want: map[string]string{
				"secretName": "mySecret",
				"namespace":  "myNamespace",
			},
		},
		{
			name:       "should return config for name 'encryption-key' and namespace 'velero'",
			secretName: "encryption-key",
			namespace:  "velero",
			want: map[string]string{
				"secretName": "encryption-key",
				"namespace":  "velero",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &secretKeyRetriever{
				secretName: tt.secretName,
				namespace:  tt.namespace,
			}
			assert.Equal(t, tt.want, s.Config())
		})
	}
}

func Test_secretKeyRetriever_GetKey(t *testing.T) {
	tests := []struct {
		name    string
		client  client.Client
		want    string
		wantErr func(t *testing.T, err error)
	}{
		{
			name:   "should fail on getting secret",
			client: fake.NewClientBuilder().Build(),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "failed to get encryption key secret 'encryption-key'")
			},
		},
		{
			name: "should fail when encryption key field in secret doesn't exist",
			client: fake.NewClientBuilder().WithObjects(
				builder.ForSecret("velero", "encryption-key").Result(),
			).Build(),
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "encryption key secret 'encryption-key' lacks field 'encryptionKey'")
			},
		},
		{
			name: "should succeed",
			client: fake.NewClientBuilder().WithObjects(
				builder.ForSecret("velero", "encryption-key").Data(map[string][]byte{"encryptionKey": []byte("mySecretEncryptionKey")}).Result(),
			).Build(),
			want: "mySecretEncryptionKey",
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &secretKeyRetriever{
				client:     tt.client,
				secretName: "encryption-key",
				namespace:  "velero",
			}

			got, err := s.GetKey()

			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
