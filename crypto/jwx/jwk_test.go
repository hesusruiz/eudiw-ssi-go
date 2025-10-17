package jwx

import (
	"crypto/ecdsa"
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/stretchr/testify/assert"
)

func TestKeyToJWK(t *testing.T) {
	for _, keyType := range crypto.GetSupportedJWKKeyTypes() {
		t.Run(string(keyType), func(tt *testing.T) {
			pub, priv, err := crypto.GenerateKeyByKeyType(keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyJWK, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(nil, priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyJWK)
			assert.NotEmpty(tt, privKeyJWK)

			otherPubKeyJWK, err := PublicKeyToPublicKeyJWK(nil, pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, otherPubKeyJWK)
			assert.Equal(tt, pubKeyJWK, otherPubKeyJWK)

			privKey, err := privKeyJWK.ToPrivateKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKey)

			pubKey, err := pubKeyJWK.ToPublicKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKey)

			if keyType == crypto.SECP256k1 {
				pubKey = crypto.SECP256k1ECDSAPubKeyToSECP256k1(pubKey.(ecdsa.PublicKey))
				privKey = crypto.SECP256k1ECDSASPrivKeyToSECP256k1(privKey.(ecdsa.PrivateKey))
			}

			assert.Equal(tt, priv, privKey)
			assert.Equal(tt, pub, pubKey)
		})
	}

	for _, keyType := range crypto.GetExperimentalKeyTypes() {
		t.Run(string(keyType), func(tt *testing.T) {
			pub, priv, err := crypto.GenerateKeyByKeyType(keyType)

			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyJWK, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(nil, priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyJWK)
			assert.NotEmpty(tt, privKeyJWK)

			otherPubKeyJWK, err := PublicKeyToPublicKeyJWK(nil, pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, otherPubKeyJWK)
			assert.Equal(tt, pubKeyJWK, otherPubKeyJWK)

			privKey, err := privKeyJWK.ToPrivateKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKey)
			assert.EqualValues(tt, priv, privKey)

			pubKey, err := pubKeyJWK.ToPublicKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKey)
			assert.EqualValues(tt, pub, pubKey)
		})
	}
}
