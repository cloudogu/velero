package encryption

// Metadata contains information about the encryption of a backup.
type Metadata struct {
	// IsEncrypted indicates whether this backup is encrypted.
	IsEncrypted bool
	// EncryptionSecret is the name of the secret containing the encryption key used for encryption.
	EncryptionSecret string
}
