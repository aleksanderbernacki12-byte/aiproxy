package securevault

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type restoreS3 struct {
	body  []byte
	input *s3.GetObjectInput
}

func (f *restoreS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.input = input
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(f.body))}, nil
}

type restoreKMS struct {
	key   []byte
	input *kms.DecryptInput
}

func (f *restoreKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.input = input
	return &kms.DecryptOutput{Plaintext: f.key}, nil
}

func TestRestoreAuthenticatesAndReturnsOriginalArchive(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte(`{"version":1,"event_id":"` + eventOne + `"}`)
	nonce, ciphertext, err := encryptAESGCM(key, plain, ObjectAssociatedData(eventOne), bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(Envelope{
		Version: 1, EventID: eventOne, Algorithm: "AES-256-GCM", KMSKeyID: "arn:aws:kms:test:key/1",
		EncryptionContext: map[string]string{"aiproxy:event_id": eventOne, "aiproxy:purpose": "securevault"}, EncryptedDataKey: []byte("encrypted"), Nonce: nonce, Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	s3Client := &restoreS3{body: envelope}
	returnedKey := append([]byte(nil), key...)
	kmsClient := &restoreKMS{key: returnedKey}
	got, err := Restore(context.Background(), RestoreConfig{KMS: kmsClient, S3: s3Client, Bucket: "evidence", Prefix: "raw", EventID: eventOne})
	if err != nil {
		t.Fatal(err)
	}
	defer zero(got)
	if !bytes.Equal(got, plain) {
		t.Fatalf("restored archive = %s", got)
	}
	if aws.ToString(s3Client.input.Bucket) != "evidence" || aws.ToString(s3Client.input.Key) != "raw/"+eventOne {
		t.Fatalf("S3 input = %#v", s3Client.input)
	}
	if aws.ToString(kmsClient.input.KeyId) != "arn:aws:kms:test:key/1" || kmsClient.input.EncryptionContext["aiproxy:event_id"] != eventOne {
		t.Fatalf("KMS input = %#v", kmsClient.input)
	}
	if !allZero(returnedKey) {
		t.Fatal("plaintext KMS data key was not erased")
	}
}

func TestRestoreRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte(`{"version":1,"event_id":"` + eventOne + `"}`)
	nonce, ciphertext, err := encryptAESGCM(key, plain, ObjectAssociatedData(eventOne), bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0xff
	envelope, _ := json.Marshal(Envelope{Version: 1, EventID: eventOne, Algorithm: "AES-256-GCM", KMSKeyID: "key", EncryptionContext: map[string]string{"aiproxy:event_id": eventOne, "aiproxy:purpose": "securevault"}, EncryptedDataKey: []byte("encrypted"), Nonce: nonce, Ciphertext: ciphertext})
	_, err = Restore(context.Background(), RestoreConfig{KMS: &restoreKMS{key: key}, S3: &restoreS3{body: envelope}, Bucket: "evidence", EventID: eventOne})
	if err == nil {
		t.Fatal("tampered archive was accepted")
	}
}
