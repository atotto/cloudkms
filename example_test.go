package cloudkms_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"log"
	"math/big"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/atotto/cloudkms"
)

func Example() {
	ctx := context.Background()

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := cloudkms.NewSigner(client, "projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<key>/cryptoKeyVersions/<version>")
	if err != nil {
		log.Fatal(err)
	}

	rootCa := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// TODO: fill
	}

	data, _ := x509.CreateCertificate(rand.Reader, rootCa, rootCa, signer.Public(), signer)
	cert, _ := x509.ParseCertificate(data)

	// Sign
	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	// Verify Signature
	if err := cert.CheckSignature(cert.SignatureAlgorithm, []byte(msg), signature); err != nil {
		log.Fatal(err)
	}
}
