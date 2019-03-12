# cloudkms

cloud kms signer

example:

```go
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
```