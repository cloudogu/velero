package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/encryption"
)

type EncryptionWriter struct {
	TarWriter
	encryptionWriter io.WriteCloser
}

func NewEncryptionWriter(t *testing.T, encryptionKey string) *EncryptionWriter {
	t.Helper()

	ew := new(EncryptionWriter)
	ew.t = t
	ew.buf = new(bytes.Buffer)

	var err error
	ew.encryptionWriter, err = encryption.NewEncryptionWriter(ew.buf, encryptionKey)
	require.NoError(t, err)

	ew.gzw = gzip.NewWriter(ew.encryptionWriter)
	ew.tw = tar.NewWriter(ew.gzw)

	return ew
}

func (ew *EncryptionWriter) AddItems(groupResource string, items ...metav1.Object) *EncryptionWriter {
	ew.t.Helper()

	ew.TarWriter.AddItems(groupResource, items...)

	return ew
}

func (ew *EncryptionWriter) Add(name string, obj interface{}) *EncryptionWriter {
	ew.t.Helper()

	ew.TarWriter.Add(name, obj)

	return ew
}

func (ew *EncryptionWriter) Done() *bytes.Buffer {
	ew.t.Helper()

	_ = ew.TarWriter.Done()
	require.NoError(ew.t, ew.encryptionWriter.Close())

	return ew.buf
}
