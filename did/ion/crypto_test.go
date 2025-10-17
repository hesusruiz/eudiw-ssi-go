package ion

import (
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestBTCSignerVerifier(t *testing.T) {
	privateKeyJWKJSON, err := getTestData("jwkes256k1private.json")
	assert.NoError(t, err)
	var privateKeyJWK jwx.PrivateKeyJWK
	err = json.Unmarshal([]byte(privateKeyJWKJSON), &privateKeyJWK)
	assert.NoError(t, err)

	signer, err := NewBTCSignerVerifier(privateKeyJWK)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	t.Run("Sign and verify", func(tt *testing.T) {
		msg := "test"
		msgHash := Hash([]byte(msg))
		signature, err := signer.Sign(msgHash)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signature)

		verified, err := signer.Verify(msgHash, signature)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})

	t.Run("Sign and verify JWS", func(tt *testing.T) {
		jwt, err := signer.SignJWT(map[string]any{"test": "data"})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwt)

		verified, err := signer.VerifyJWS(jwt)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
}
