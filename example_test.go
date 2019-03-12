package cloudkms_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"log"

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
		// TODO: fill
	}

	x509.CreateCertificate(rand.Reader, rootCa, rootCa, signer.Public(), signer)
}
