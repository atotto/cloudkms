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
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type Signer struct {
	keyPath     string
	client      *kms.KeyManagementClient
	signTimeout time.Duration

	algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm

	pubKey crypto.PublicKey
}

func NewSigner(client *kms.KeyManagementClient, keyPath string) (*Signer, error) {
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, 10*time.Second)

	pubKeypb, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %s", err)
	}

	block, _ := pem.Decode([]byte(pubKeypb.Pem))
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %s", err)
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

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	ctx, _ = context.WithTimeout(context.Background(), s.signTimeout)

	var kmsDigest *kmspb.Digest

	switch s.algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		kmsDigest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		}
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		kmsDigest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest,
			},
		}
	default:
		return nil, fmt.Errorf("not implemented yet: %s", s.algorithm.String())
	}

	res, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   s.keyPath,
		Digest: kmsDigest,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return res.GetSignature(), nil
}
