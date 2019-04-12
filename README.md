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
		SerialNumber: big.NewInt(1),
		// TODO: fill
	}

	data, _ := x509.CreateCertificate(rand.Reader, rootCa, rootCa, signer.Public(), signer)
	cert, _ := x509.ParseCertificate(data)

	// Sign
	msg := "hello, world"
	h := signer.HashFunc().New()
	h.Write([]byte(msg))
	digest := h.Sum(nil)
	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	// Verify Signature
	if err := cert.CheckSignature(cert.SignatureAlgorithm, []byte(msg), signature); err != nil {
		log.Fatal(err)
	}
```