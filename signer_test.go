package cloudkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
)

// fakeKMSClient is a mock kmsClient for testing.
type fakeKMSClient struct {
	pubKeyPEM string
	algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	// Captures the last AsymmetricSign request for assertion.
	lastSignReq *kmspb.AsymmetricSignRequest
}

func (f *fakeKMSClient) GetPublicKey(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	return &kmspb.PublicKey{
		Pem:       f.pubKeyPEM,
		Algorithm: f.algorithm,
	}, nil
}

func (f *fakeKMSClient) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.lastSignReq = req
	// Return a dummy signature (not cryptographically valid, but sufficient for unit tests).
	return &kmspb.AsymmetricSignResponse{Signature: []byte("dummy-signature")}, nil
}

// generateECPEMPublicKey generates a throwaway EC P-256 public key in PEM form.
func generateECPEMPublicKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestHashFunc verifies that HashFunc returns the correct crypto.Hash for each algorithm.
func TestHashFunc(t *testing.T) {
	tests := []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		want      crypto.Hash
	}{
		// SHA-256
		{"RSA_PKCS1_2048_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, crypto.SHA256},
		{"RSA_PKCS1_3072_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, crypto.SHA256},
		{"RSA_PKCS1_4096_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, crypto.SHA256},
		{"RSA_PSS_2048_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, crypto.SHA256},
		{"RSA_PSS_3072_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, crypto.SHA256},
		{"RSA_PSS_4096_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, crypto.SHA256},
		{"EC_P256_SHA256", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, crypto.SHA256},
		{"EC_SECP256K1_SHA256", kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256, crypto.SHA256},
		// SHA-384
		{"EC_P384_SHA384", kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, crypto.SHA384},
		// SHA-512
		{"RSA_PKCS1_4096_SHA512", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, crypto.SHA512},
		{"RSA_PSS_4096_SHA512", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, crypto.SHA512},
		// No pre-hashing (Hash = 0)
		{"EC_ED25519", kmspb.CryptoKeyVersion_EC_SIGN_ED25519, crypto.Hash(0)},
		{"RSA_RAW_PKCS1_2048", kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048, crypto.Hash(0)},
		{"RSA_RAW_PKCS1_3072", kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072, crypto.Hash(0)},
		{"RSA_RAW_PKCS1_4096", kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096, crypto.Hash(0)},
		{"PQ_ML_DSA_65", kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, crypto.Hash(0)},
		{"PQ_SLH_DSA_SHA2_128S", kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S, crypto.Hash(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{algorithm: tt.algorithm}
			got := s.HashFunc()
			if got != tt.want {
				t.Errorf("HashFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSign_DigestField verifies that Sign sends a Digest (not Data) for hash-based algorithms.
func TestSign_DigestField(t *testing.T) {
	pubKeyPEM := generateECPEMPublicKey(t)

	tests := []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		wantHash  string // "sha256", "sha384", "sha512"
	}{
		{"EC_P256_SHA256", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "sha256"},
		{"EC_P384_SHA384", kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, "sha384"},
		{"RSA_PKCS1_4096_SHA512", kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, "sha512"},
		{"RSA_PSS_2048_SHA256", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, "sha256"},
		{"EC_SECP256K1_SHA256", kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256, "sha256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeKMSClient{pubKeyPEM: pubKeyPEM, algorithm: tt.algorithm}
			s, err := newSigner(fake, "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1")
			if err != nil {
				t.Fatalf("newSigner: %v", err)
			}

			digest := make([]byte, 32)
			_, _ = rand.Read(digest)

			if _, err := s.Sign(nil, digest, nil); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			req := fake.lastSignReq
			if req == nil {
				t.Fatal("AsymmetricSign was not called")
			}
			if req.Data != nil {
				t.Error("expected Digest field, but Data was set")
			}
			if req.Digest == nil {
				t.Fatal("Digest field is nil")
			}

			switch tt.wantHash {
			case "sha256":
				if req.Digest.GetSha256() == nil {
					t.Errorf("expected Sha256 digest, got %T", req.Digest.Digest)
				}
			case "sha384":
				if req.Digest.GetSha384() == nil {
					t.Errorf("expected Sha384 digest, got %T", req.Digest.Digest)
				}
			case "sha512":
				if req.Digest.GetSha512() == nil {
					t.Errorf("expected Sha512 digest, got %T", req.Digest.Digest)
				}
			}
		})
	}
}

// TestSign_DataField verifies that Sign sends Data (not Digest) for raw/no-prehash algorithms.
func TestSign_DataField(t *testing.T) {
	pubKeyPEM := generateECPEMPublicKey(t)

	tests := []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	}{
		{"EC_ED25519", kmspb.CryptoKeyVersion_EC_SIGN_ED25519},
		{"RSA_RAW_PKCS1_2048", kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048},
		{"PQ_ML_DSA_65", kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65},
		{"PQ_SLH_DSA_SHA2_128S", kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeKMSClient{pubKeyPEM: pubKeyPEM, algorithm: tt.algorithm}
			s, err := newSigner(fake, "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1")
			if err != nil {
				t.Fatalf("newSigner: %v", err)
			}

			message := []byte("hello, world")
			if _, err := s.Sign(nil, message, nil); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			req := fake.lastSignReq
			if req == nil {
				t.Fatal("AsymmetricSign was not called")
			}
			if req.Digest != nil {
				t.Error("expected Data field, but Digest was set")
			}
			if string(req.Data) != string(message) {
				t.Errorf("Data = %q, want %q", req.Data, message)
			}
		})
	}
}
