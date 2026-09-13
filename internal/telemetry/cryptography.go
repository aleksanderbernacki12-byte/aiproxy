package telemetry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	exchangeHashDomain = "aiproxy-telemetry-exchange-v1\x00"
	eventHashDomain    = "aiproxy-telemetry-event-v1\x00"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func loadPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, fmt.Errorf("telemetry: inspect ECDSA private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("telemetry: ECDSA private key must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("telemetry: ECDSA private key permissions %04o expose it to group or others", info.Mode().Perm())
	}
	encoded, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("telemetry: read ECDSA private key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	for index := range encoded {
		encoded[index] = 0
	}
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("telemetry: private key file must contain exactly one PEM block")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*ecdsa.PrivateKey)
			if !ok {
				err = errors.New("PKCS#8 key is not ECDSA")
			}
		}
	default:
		err = fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	for index := range block.Bytes {
		block.Bytes[index] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("telemetry: parse ECDSA private key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("telemetry: ECDSA private key must use curve P-256")
	}
	return key, nil
}

func keyID(publicKey *ecdsa.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// HashExchange creates an unambiguous SHA-256 commitment to the exact request
// and response byte sequences. Length prefixes prevent concatenation attacks.
func HashExchange(request, response []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(exchangeHashDomain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(request)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(request)
	binary.BigEndian.PutUint64(length[:], uint64(len(response)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(response)
	return hex.EncodeToString(hash.Sum(nil))
}

func finalizePayload(payload Payload, key *ecdsa.PrivateKey) (Payload, error) {
	payload.Cryptography.EventHash = ""
	payload.Cryptography.Signature = ""
	draft, err := canonicalJSON(payload)
	if err != nil {
		return Payload{}, fmt.Errorf("encode event hash input: %w", err)
	}
	eventDigest := sha256.Sum256(append([]byte(eventHashDomain), draft...))
	payload.Cryptography.EventHash = hex.EncodeToString(eventDigest[:])

	signingBytes, err := SigningBytes(payload)
	if err != nil {
		return Payload{}, err
	}
	signingDigest := sha256.Sum256(signingBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, key, signingDigest[:])
	if err != nil {
		return Payload{}, fmt.Errorf("sign payload: %w", err)
	}
	payload.Cryptography.Signature = base64.RawStdEncoding.EncodeToString(signature)
	return payload, nil
}

// SigningBytes returns the canonical JSON representation covered by the ECDSA
// signature. The signature field is present as an empty string to avoid the
// self-reference inherent in embedding a signature in its own payload.
func SigningBytes(payload Payload) ([]byte, error) {
	payload.Cryptography.Signature = ""
	encoded, err := canonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("encode signing input: %w", err)
	}
	return encoded, nil
}

// Verify checks the event hash and ECDSA signature. The control plane can use
// this without receiving the raw request or response.
func Verify(payload Payload, publicKey *ecdsa.PublicKey) error {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return errors.New("telemetry: P-256 public key is required")
	}
	wantEventHash := payload.Cryptography.EventHash
	draft := payload
	draft.Cryptography.EventHash = ""
	draft.Cryptography.Signature = ""
	encodedDraft, err := canonicalJSON(draft)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(eventHashDomain), encodedDraft...))
	if !strings.EqualFold(wantEventHash, hex.EncodeToString(digest[:])) {
		return errors.New("telemetry: event hash mismatch")
	}

	signature, err := base64.RawStdEncoding.DecodeString(payload.Cryptography.Signature)
	if err != nil {
		return errors.New("telemetry: invalid base64 signature")
	}
	var parsed ecdsaSignature
	if rest, err := asn1.Unmarshal(signature, &parsed); err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return errors.New("telemetry: invalid ASN.1 ECDSA signature")
	}
	signingBytes, err := SigningBytes(payload)
	if err != nil {
		return err
	}
	signingDigest := sha256.Sum256(signingBytes)
	if !ecdsa.Verify(publicKey, signingDigest[:], parsed.R, parsed.S) {
		return errors.New("telemetry: signature verification failed")
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return nil, fmt.Errorf("canonicalize JSON using RFC 8785: %w", err)
	}
	return canonical, nil
}
