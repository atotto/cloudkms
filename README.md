# cloudkms

A `crypto.Signer` implementation backed by [Google Cloud KMS](https://cloud.google.com/kms) asymmetric signing keys.

**Features:**

- Implements `crypto.Signer`, so it works directly with Go standard library APIs such as `tls.Certificate` and `x509.CreateCertificate`.
- Supports all Cloud KMS signing algorithms: RSA (PKCS#1 / PSS), EC (P-256 / P-384 / secp256k1), Ed25519, and post-quantum (ML-DSA / SLH-DSA).
- Automatically detects the algorithm from the key, so callers do not need to specify it.

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
```