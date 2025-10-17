package parsing

import (
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/credential"
	"github.com/hesusruiz/eudiw-ssi-go/credential/integrity"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite"
	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite/jws2020"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestCredentialsFromInterface(t *testing.T) {
	t.Run("Bad Cred", func(tt *testing.T) {
		_, _, parsedCred, err := ToCredential("bad")
		assert.Error(tt, err)
		assert.Empty(tt, parsedCred)

		genericCred, err := ToCredentialJSONMap("bad")
		assert.Error(tt, err)
		assert.Empty(tt, genericCred)
	})

	t.Run("Unsigned Cred", func(tt *testing.T) {
		testCred := getTestCredential()

		_, _, parsedCred, err := ToCredential(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.Equal(tt, testCred.Issuer, parsedCred.Issuer)

		genericCred, err := ToCredentialJSONMap(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, testCred.Issuer, genericCred["issuer"])
	})

	t.Run("Data Integrity Cred", func(tt *testing.T) {
		knownJWK := jws2020.JSONWebKey2020{
			ID: "did:example:123#key-0",
			PublicKeyJWK: jwx.PublicKeyJWK{
				KID: "key-0",
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			},
			PrivateKeyJWK: jwx.PrivateKeyJWK{
				KID: "key-0",
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
				D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
			},
		}

		signer, err := jws2020.NewJSONWebKeySigner("issuer-id", knownJWK.PrivateKeyJWK, cryptosuite.AssertionMethod)
		assert.NoError(t, err)

		suite := jws2020.GetJSONWebSignature2020Suite()

		testCred := getTestCredential()
		err = suite.Sign(signer, &testCred)
		assert.NoError(t, err)

		_, _, parsedCred, err := ToCredential(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.Equal(tt, testCred.Issuer, parsedCred.Issuer)

		genericCred, err := ToCredentialJSONMap(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, parsedCred.Issuer, genericCred["issuer"])
	})

	t.Run("Data Integrity Cred as a JSON string", func(tt *testing.T) {
		knownJWK := jws2020.JSONWebKey2020{
			ID: "did:example:123#key-0",
			PublicKeyJWK: jwx.PublicKeyJWK{
				KID: "key-0",
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			},
			PrivateKeyJWK: jwx.PrivateKeyJWK{
				KID: "key-0",
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
				D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
			},
		}

		signer, err := jws2020.NewJSONWebKeySigner("issuer-id", knownJWK.PrivateKeyJWK, cryptosuite.AssertionMethod)
		assert.NoError(t, err)

		suite := jws2020.GetJSONWebSignature2020Suite()

		testCred := getTestCredential()
		err = suite.Sign(signer, &testCred)
		assert.NoError(t, err)

		credBytes, err := json.Marshal(testCred)
		assert.NoError(t, err)
		credJSON := string(credBytes)

		_, _, parsedCred, err := ToCredential(credJSON)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.Equal(tt, testCred.Issuer, parsedCred.Issuer)

		genericCred, err := ToCredentialJSONMap(credJSON)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, parsedCred.Issuer, genericCred["issuer"])
	})

	t.Run("JWT Cred", func(tt *testing.T) {
		knownJWK := jwx.PrivateKeyJWK{
			KID: "key-0",
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		}

		signer, err := jwx.NewJWXSignerFromJWK("signer-id", knownJWK)
		assert.NoError(tt, err)

		testCred := getTestCredential()
		signed, err := integrity.SignVerifiableCredentialJWT(*signer, testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signed)

		headers, token, parsedCred, err := ToCredential(string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.NotEmpty(tt, headers)
		assert.NotEmpty(tt, token)
		assert.Equal(tt, parsedCred.Issuer, testCred.Issuer)
		gotIss, ok := token.Get("iss")
		assert.True(tt, ok)
		assert.Equal(tt, gotIss.(string), testCred.Issuer)

		genericCred, err := ToCredentialJSONMap(string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, parsedCred.Issuer, genericCred["iss"])
	})
}

func getTestCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}
}
