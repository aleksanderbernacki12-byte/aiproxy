package securevault

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type preflightKMS struct {
	plaintext []byte
	err       error
	input     *kms.GenerateDataKeyInput
}

func (f *preflightKMS) GenerateDataKey(_ context.Context, input *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	return &kms.GenerateDataKeyOutput{Plaintext: f.plaintext, CiphertextBlob: []byte("encrypted")}, nil
}

type preflightS3 struct {
	enabled bool
	err     error
	bucket  string
}

func (f *preflightS3) GetObjectLockConfiguration(_ context.Context, input *s3.GetObjectLockConfigurationInput, _ ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if input.Bucket != nil {
		f.bucket = *input.Bucket
	}
	if f.err != nil {
		return nil, f.err
	}
	configuration := &s3types.ObjectLockConfiguration{}
	if f.enabled {
		configuration.ObjectLockEnabled = s3types.ObjectLockEnabledEnabled
	}
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: configuration}, nil
}

func TestCheckAWSConfigVerifiesKMSAndObjectLock(t *testing.T) {
	plain := make([]byte, 32)
	kmsClient := &preflightKMS{plaintext: plain}
	s3Client := &preflightS3{enabled: true}
	if err := CheckAWSConfig(context.Background(), kmsClient, s3Client, "alias/aiproxy", "evidence"); err != nil {
		t.Fatal(err)
	}
	if kmsClient.input == nil || kmsClient.input.EncryptionContext["aiproxy:purpose"] != "securevault" {
		t.Fatal("KMS preflight did not use the production encryption context")
	}
	if s3Client.bucket != "evidence" {
		t.Fatalf("bucket = %q", s3Client.bucket)
	}
	for _, value := range plain {
		if value != 0 {
			t.Fatal("plaintext data key was not cleared")
		}
	}
}

func TestCheckAWSConfigRejectsUnavailablePrerequisites(t *testing.T) {
	for name, clients := range map[string]struct {
		kms *preflightKMS
		s3  *preflightS3
	}{
		"kms":         {&preflightKMS{err: errors.New("denied")}, &preflightS3{enabled: true}},
		"object lock": {&preflightKMS{plaintext: make([]byte, 32)}, &preflightS3{}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckAWSConfig(context.Background(), clients.kms, clients.s3, "alias/aiproxy", "evidence"); err == nil {
				t.Fatal("preflight unexpectedly succeeded")
			}
		})
	}
}
