package securevault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const maxArchiveObjectBytes = 64 << 20

type KMSDecryptClient interface {
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type S3GetClient interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type RestoreConfig struct {
	KMS     KMSDecryptClient
	S3      S3GetClient
	Bucket  string
	Prefix  string
	EventID string
}

// Restore downloads and decrypts one customer-owned evidence record. The
// returned bytes are the original archive JSON and contain sensitive raw data.
func Restore(ctx context.Context, cfg RestoreConfig) ([]byte, error) {
	if cfg.KMS == nil || cfg.S3 == nil {
		return nil, errors.New("securevault: KMS and S3 clients are required")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("securevault: S3 bucket is required")
	}
	if !validUUID(cfg.EventID) {
		return nil, ErrInvalidEventID
	}
	eventID := strings.ToLower(cfg.EventID)
	objectKey := eventID
	if prefix := strings.Trim(cfg.Prefix, "/"); prefix != "" {
		objectKey = path.Join(prefix, eventID)
	}
	object, err := cfg.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(cfg.Bucket), Key: aws.String(objectKey)})
	if err != nil {
		return nil, fmt.Errorf("securevault: get S3 object: %w", err)
	}
	if object == nil || object.Body == nil {
		return nil, errors.New("securevault: S3 returned an empty object")
	}
	defer object.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(object.Body, maxArchiveObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("securevault: read S3 object: %w", err)
	}
	if len(encoded) > maxArchiveObjectBytes {
		return nil, errors.New("securevault: S3 object exceeds 64 MiB safety limit")
	}
	var envelope Envelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("securevault: decode envelope: %w", err)
	}
	if envelope.Version != 1 || envelope.EventID != eventID || envelope.Algorithm != "AES-256-GCM" || len(envelope.EncryptedDataKey) == 0 {
		return nil, errors.New("securevault: invalid envelope metadata")
	}
	if envelope.EncryptionContext["aiproxy:event_id"] != eventID || envelope.EncryptionContext["aiproxy:purpose"] != "securevault" || strings.TrimSpace(envelope.KMSKeyID) == "" {
		return nil, errors.New("securevault: invalid envelope encryption context")
	}
	keyOutput, err := cfg.KMS.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    envelope.EncryptedDataKey,
		EncryptionContext: envelope.EncryptionContext,
		KeyId:             aws.String(envelope.KMSKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("securevault: decrypt data key: %w", err)
	}
	if keyOutput == nil || len(keyOutput.Plaintext) != 32 {
		if keyOutput != nil {
			zero(keyOutput.Plaintext)
		}
		return nil, errors.New("securevault: KMS returned an invalid AES-256 data key")
	}
	key := keyOutput.Plaintext
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("securevault: initialize AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("securevault: initialize GCM: %w", err)
	}
	if len(envelope.Nonce) != gcm.NonceSize() {
		return nil, errors.New("securevault: invalid AES-GCM nonce")
	}
	plain, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, ObjectAssociatedData(eventID))
	if err != nil {
		return nil, fmt.Errorf("securevault: authenticate archive: %w", err)
	}
	var record struct {
		Version int    `json:"version"`
		EventID string `json:"event_id"`
	}
	if json.Unmarshal(plain, &record) != nil || record.Version != 1 || record.EventID != eventID {
		zero(plain)
		return nil, errors.New("securevault: decrypted archive identity mismatch")
	}
	return plain, nil
}
