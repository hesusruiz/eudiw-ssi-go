package integrity

import (
	"context"
	"testing"
	"time"

	"github.com/hesusruiz/eudiw-ssi-go/credential"
	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/did/key"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifiableCredentialJWT(t *testing.T) {
	testCredential := credential.VerifiableCredential{
		ID:           "http://example.edu/credentials/1872",
		Context:      []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:example:123",
		IssuanceDate: "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id":   "did:example:456",
			"name": "JimBobertson",
		},
	}

	t.Run("Known JWK Signer", func(t *testing.T) {
		signer := getTestVectorKey0Signer(t)
		signed, err := SignVerifiableCredentialJWT(signer, testCredential)
		assert.NoError(t, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(t, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(t, err)

		parsedHeaders, parsedJWT, parsedCred, err := ParseVerifiableCredentialFromJWT(token)
		assert.NoError(t, err)
		assert.NotEmpty(t, parsedJWT)
		assert.NotEmpty(t, parsedCred)
		assert.NotEmpty(t, parsedHeaders)

		headers, verifiedJWT, cred, err := VerifyVerifiableCredentialJWT(*verifier, token)
		assert.NoError(t, err)
		assert.NotEmpty(t, verifiedJWT)
		assert.NotEmpty(t, cred)
		assert.NotEmpty(t, headers)
		assert.Equal(t, parsedJWT, verifiedJWT)
		assert.Equal(t, parsedCred, cred)
		assert.Equal(t, parsedHeaders, headers)
	})

	t.Run("Generated Private Key For Signer", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)

		signer, err := jwx.NewJWXSigner("test-id", nil, privKey)
		assert.NoError(tt, err)

		signed, err := SignVerifiableCredentialJWT(*signer, testCredential)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(tt, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(tt, err)

		parsedHeaders, parsedJWT, parsedCred, err := ParseVerifiableCredentialFromJWT(token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedJWT)
		assert.NotEmpty(tt, parsedHeaders)
		assert.NotEmpty(tt, parsedCred)

		verifiedHeaders, verifiedJWT, cred, err := VerifyVerifiableCredentialJWT(*verifier, token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedJWT)
		assert.Equal(tt, parsedJWT, verifiedJWT)
		assert.Equal(tt, parsedCred, cred)
		assert.Equal(tt, parsedHeaders, verifiedHeaders)
	})
}

func TestVerifiablePresentationJWT(t *testing.T) {
	t.Run("bad audience", func(tt *testing.T) {
		signer := getTestVectorKey0Signer(tt)

		testPresentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			Type:   []string{"VerifiablePresentation"},
			Holder: signer.ID,
		}

		signed, err := SignVerifiablePresentationJWT(signer, &JWTVVPParameters{Audience: []string{"bad-audience"}}, testPresentation)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(tt, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(tt, err)

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		require.NoError(tt, err)
		require.NotEmpty(tt, resolver)

		_, _, _, err = VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, token)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "audience mismatch")
	})

	t.Run("no audience", func(tt *testing.T) {
		signer := getTestVectorKey0Signer(tt)

		testPresentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			Type:   []string{"VerifiablePresentation"},
			Holder: signer.ID,
		}

		signed, err := SignVerifiablePresentationJWT(signer, nil, testPresentation)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(tt, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(tt, err)

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		require.NoError(tt, err)
		require.NotEmpty(tt, resolver)

		_, _, _, err = VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, token)
		assert.NoError(tt, err)
	})

	t.Run("no VCs", func(tt *testing.T) {
		signer := getTestVectorKey0Signer(tt)

		testPresentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			Type:   []string{"VerifiablePresentation"},
			Holder: signer.ID,
		}

		signed, err := SignVerifiablePresentationJWT(signer, &JWTVVPParameters{Audience: []string{signer.ID}}, testPresentation)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(tt, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(tt, err)

		parsedHeaders, parsedJWT, parsedPres, err := ParseVerifiablePresentationFromJWT(token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedJWT)
		assert.NotEmpty(tt, parsedHeaders)
		assert.NotEmpty(tt, parsedPres)

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		require.NoError(tt, err)
		require.NotEmpty(tt, resolver)

		parsedHeaders, verifiedJWT, pres, err := VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedJWT)
		assert.NotEmpty(tt, parsedHeaders)
		assert.Equal(tt, parsedJWT, verifiedJWT)
		assert.Equal(tt, parsedPres, pres)
	})

	t.Run("with VC a single valid VC JWT", func(tt *testing.T) {
		issuerPrivKey, issuerDID, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerPrivKey)
		assert.NotEmpty(tt, issuerDID)
		expandedIssuerDID, err := issuerDID.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, expandedIssuerDID)
		issuerKID := expandedIssuerDID.VerificationMethod[0].ID
		assert.NotEmpty(tt, issuerKID)

		subjectPrivKey, subjectDID, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, subjectPrivKey)
		assert.NotEmpty(tt, subjectDID)
		expandedSubjectDID, err := subjectDID.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, expandedSubjectDID)
		subjectKID := expandedSubjectDID.VerificationMethod[0].ID
		assert.NotEmpty(tt, subjectKID)

		testCredential := credential.VerifiableCredential{
			ID:           uuid.NewString(),
			Context:      []any{"https://www.w3.org/2018/credentials/v1"},
			Type:         []string{"VerifiableCredential"},
			Issuer:       issuerDID.String(),
			IssuanceDate: time.Now().Format(time.RFC3339),
			CredentialSubject: map[string]any{
				"id":   subjectDID.String(),
				"name": "Toshi",
			},
		}

		issuerSigner, err := jwx.NewJWXSigner(issuerDID.String(), &issuerKID, issuerPrivKey)
		assert.NoError(tt, err)
		signedVC, err := SignVerifiableCredentialJWT(*issuerSigner, testCredential)
		assert.NoError(t, err)

		testPresentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Type:    []string{"VerifiablePresentation"},
			Holder:  subjectDID.String(),
			VerifiableCredential: []any{
				string(signedVC),
			},
		}

		// sign the presentation from the subject to the issuer
		subjectSigner, err := jwx.NewJWXSigner(subjectDID.String(), &subjectKID, subjectPrivKey)
		assert.NoError(tt, err)
		signed, err := SignVerifiablePresentationJWT(*subjectSigner, &JWTVVPParameters{Audience: []string{issuerDID.String()}}, testPresentation)
		assert.NoError(tt, err)

		// parse the VP
		parsedHeaders, parsedJWT, parsedPres, err := ParseVerifiablePresentationFromJWT(string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedJWT)
		assert.NotEmpty(tt, parsedHeaders)
		assert.NotEmpty(tt, parsedPres)

		// Verify the VP JWT
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		require.NoError(tt, err)
		require.NotEmpty(tt, resolver)

		verifier, err := subjectSigner.ToVerifier(issuerDID.String())
		assert.NoError(tt, err)
		parsedHeaders, verifiedJWT, pres, err := VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedJWT)
		assert.NotEmpty(tt, parsedHeaders)
		assert.Equal(tt, parsedJWT, verifiedJWT)
		assert.Equal(tt, parsedPres, pres)
	})
}

func getTestVectorKey0Signer(t *testing.T) jwx.Signer {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	knownJWK := jwx.PrivateKeyJWK{
		KID: "key-0",
		KTY: "OKP",
		CRV: "Ed25519",
		X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
	}

	signer, err := jwx.NewJWXSignerFromJWK("signer-id", knownJWK)
	require.NoError(t, err)
	return *signer
}
