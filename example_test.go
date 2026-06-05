package cloudkms_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
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
	msg := []byte("hello, world")
	var input []byte
	if h := signer.HashFunc(); h != 0 {
		hh := h.New()
		hh.Write(msg)
		input = hh.Sum(nil)
	} else {
		// Algorithm handles hashing internally (e.g. Ed25519); pass raw message.
		input = msg
	}
	signature, err := signer.Sign(rand.Reader, input, signer.HashFunc())
	if err != nil {
		log.Fatal(err)
	}

	// Verify Signature
	if err := cert.CheckSignature(cert.SignatureAlgorithm, msg, signature); err != nil {
		log.Fatal(err)
	}

	fmt.Println("OK")
}
