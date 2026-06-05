package cloudkms

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
)

// kmsClient is the subset of kms.KeyManagementClient used by Signer.
type kmsClient interface {
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// Signer implements crypto.Signer interface.
type Signer struct {
	keyPath     string
	client      kmsClient
	signTimeout time.Duration

	algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm

	pubKey crypto.PublicKey
}

func NewSigner(client *kms.KeyManagementClient, keyPath string) (*Signer, error) {
	return newSigner(client, keyPath)
}

func newSigner(client kmsClient, keyPath string) (*Signer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pubKeypb, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	block, _ := pem.Decode([]byte(pubKeypb.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from public key response")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Signer{
		keyPath:     keyPath,
		client:      client,
		signTimeout: 15 * time.Second,
		algorithm:   pubKeypb.Algorithm,
		pubKey:      pubKey,
	}, nil
}

func (s *Signer) Public() crypto.PublicKey {
	return s.pubKey
}

// digestKind classifies the signing algorithm by how the digest/data should be prepared.
type digestKind int

const (
	digestKindSHA256 digestKind = iota
	digestKindSHA384
	digestKindSHA512
	digestKindRaw // no pre-hashing; pass raw data to KMS
	digestKindUnknown
)

func (s *Signer) getDigestKind() digestKind {
	switch s.algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return digestKindSHA256
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return digestKindSHA384
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return digestKindSHA512
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65,
		kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S:
		return digestKindRaw
	default:
		return digestKindUnknown
	}
}

func (s *Signer) HashFunc() crypto.Hash {
	switch s.getDigestKind() {
	case digestKindSHA256:
		return crypto.SHA256
	case digestKindSHA384:
		return crypto.SHA384
	case digestKindSHA512:
		return crypto.SHA512
	case digestKindRaw:
		// These algorithms handle hashing internally or use raw data; no pre-hashing required.
		return crypto.Hash(0)
	default:
		return 0
	}
}

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.signTimeout)
	defer cancel()

	var req *kmspb.AsymmetricSignRequest

	switch s.getDigestKind() {
	case digestKindSHA256:
		req = &kmspb.AsymmetricSignRequest{
			Name:   s.keyPath,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		}
	case digestKindSHA384:
		req = &kmspb.AsymmetricSignRequest{
			Name:   s.keyPath,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}},
		}
	case digestKindSHA512:
		req = &kmspb.AsymmetricSignRequest{
			Name:   s.keyPath,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}},
		}
	case digestKindRaw:
		req = &kmspb.AsymmetricSignRequest{
			Name: s.keyPath,
			Data: digest,
		}
	default:
		return nil, fmt.Errorf("not implemented yet: %s", s.algorithm.String())
	}

	res, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return res.GetSignature(), nil
}
