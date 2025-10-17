package jws2020

import (
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite"
	"github.com/stretchr/testify/assert"
)

func TestJSONWebKey2020SignerVerifier(t *testing.T) {
	signerID := "signer-id"
	tests := []struct {
		name string
		kty  KTY
		crv  CRV
	}{
		{
			name: "RSA-2048",
			kty:  RSA,
		},
		{
			name: "Ed25519",
			kty:  OKP,
			crv:  Ed25519,
		},
		{
			name: "secpk256k1",
			kty:  EC,
			crv:  SECP256k1,
		},
		{
			name: "P-256",
			kty:  EC,
			crv:  P256,
		},
		{
			name: "P-384",
			kty:  EC,
			crv:  P384,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kty := test.kty
			crv := test.crv
			jwk, err := GenerateJSONWebKey2020(kty, crv)
			assert.NoError(t, err)
			assert.NotEmpty(t, jwk)

			signer, err := NewJSONWebKeySigner(signerID, jwk.PrivateKeyJWK, cryptosuite.AssertionMethod)
			assert.NoError(t, err)

			testMessage := []byte("my name is satoshi")
			signature, err := signer.Sign(testMessage)
			assert.NoError(t, err)
			assert.NotEmpty(t, signature)

			verifier, err := NewJSONWebKeyVerifier(signerID, jwk.PublicKeyJWK)
			assert.NoError(t, err)
			assert.NotEmpty(t, verifier)

			err = verifier.Verify(testMessage, signature)
			assert.NoError(t, err)
		})
	}
}
