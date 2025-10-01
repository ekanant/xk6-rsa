package crypto_x25519

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/rsa", new(Rsa))
}

type Rsa struct{}

func (Rsa) EncryptPKCS1v15(plainText string, publicKeyPem string) []byte {
	publickey, err := parsePublicKeyFromPEM([]byte(publicKeyPem))
	if err != nil {
		panic(err)
	}

	// Encrypt the message using PKCS#1 v1.5 padding
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publickey, []byte(plainText))
	if err != nil {
		panic(err)
	}
	return ciphertext
}

// parsePublicKeyFromPEM parses PEM data to *rsa.PublicKey.
func parsePublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubIfc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return pub, nil
}
