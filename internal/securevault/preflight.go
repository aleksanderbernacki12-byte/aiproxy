package securevault

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const preflightEventID = "00000000-0000-4000-8000-000000000000"

type ObjectLockClient interface {
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
}

// CheckAWSConfig verifies the two AWS prerequisites that can be tested without
// writing an immutable evidence object: KMS GenerateDataKey and S3 Object Lock.
// PutObject permission is exercised only by a real archive upload.
func CheckAWSConfig(ctx context.Context, kmsClient KMSClient, s3Client ObjectLockClient, keyID, bucket string) error {
	if kmsClient == nil || s3Client == nil {
		return errors.New("securevault: KMS and S3 clients are required")
	}
	if strings.TrimSpace(keyID) == "" || strings.TrimSpace(bucket) == "" {
		return errors.New("securevault: KMS key ID and S3 bucket are required")
	}
	key, err := kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: kmstypes.DataKeySpecAes256,
		EncryptionContext: map[string]string{
			"aiproxy:event_id": preflightEventID,
			"aiproxy:purpose":  "securevault",
		},
	})
	if err != nil {
		return fmt.Errorf("securevault: verify KMS GenerateDataKey: %w", err)
	}
	if key == nil {
		return errors.New("securevault: verify KMS GenerateDataKey: empty response")
	}
	defer zero(key.Plaintext)
	if len(key.Plaintext) != 32 || len(key.CiphertextBlob) == 0 {
		return errors.New("securevault: verify KMS GenerateDataKey: invalid AES-256 data key")
	}
	lock, err := s3Client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return fmt.Errorf("securevault: verify S3 Object Lock: %w", err)
	}
	if lock == nil || lock.ObjectLockConfiguration == nil || lock.ObjectLockConfiguration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
		return errors.New("securevault: S3 Object Lock is not enabled")
	}
	return nil
}
