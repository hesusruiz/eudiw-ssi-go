package integrity

import (
	"context"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/hesusruiz/eudiw-ssi-go/credential"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/did/key"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"
	"github.com/hesusruiz/eudiw-ssi-go/did/web"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCredentialSignature(t *testing.T) {
	t.Run("empty credential", func(tt *testing.T) {
		_, err := VerifyCredentialSignature(context.Background(), nil, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential cannot be empty")
	})

	t.Run("empty resolution", func(tt *testing.T) {
		_, err := VerifyCredentialSignature(context.Background(), "not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolution cannot be empty")
	})

	t.Run("invalid credential type - int", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), 5, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid credential type: int")
	})

	t.Run("empty map credential type", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), map[string]any{"a": "test"}, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "map is not a valid credential")
	})

	t.Run("data integrity map credential type missing proof", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		cred := getTestCredential()
		_, err = VerifyCredentialSignature(context.Background(), cred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("data integrity credential - no proof", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		cred := getTestCredential()
		_, err = VerifyCredentialSignature(context.Background(), cred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")

		// test with a pointer
		_, err = VerifyCredentialSignature(context.Background(), &cred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("data integrity credential - as bytes and string", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		testCred := getTestCredential()
		credBytes, err := json.Marshal(testCred)

		assert.NoError(tt, err)
		_, err = VerifyCredentialSignature(context.Background(), credBytes, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")

		// test with a string
		_, err = VerifyCredentialSignature(context.Background(), string(credBytes), resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("jwt credential - as bytes and string", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		verified, err := VerifyCredentialSignature(context.Background(), jwtCred, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)

		// test with bytes
		verified, err = VerifyCredentialSignature(context.Background(), []byte(jwtCred), resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
}

func TestVerifyJWTCredential(t *testing.T) {
	t.Run("empty credential", func(tt *testing.T) {
		_, err := VerifyJWTCredential(context.Background(), "", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential cannot be empty")
	})

	t.Run("empty resolution", func(tt *testing.T) {
		_, err := VerifyJWTCredential(context.Background(), "not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolution cannot be empty")
	})

	t.Run("invalid credential", func(tt *testing.T) {
		r, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, err = VerifyJWTCredential(context.Background(), "not-empty", r)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})

	t.Run("valid credential, not signed by DID", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner("test-id", nil, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting issuer DID<test-id> to verify credential")
	})

	t.Run("valid credential, signed by DID the resolution can't resolve", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{web.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: key")
	})

	t.Run("valid credential, kid not found", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner(didKey.String(), nil, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no verification methods with kid: ")
	})

	t.Run("valid credential, bad signature", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)

		// modify the signature to make it invalid
		jwtCred = jwtCred[:len(jwtCred)-5] + "baddata"

		verified, err := VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.False(tt, verified)
	})

	t.Run("valid credential", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		verified, err := VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})

}

func getTestJWTCredential(t *testing.T, signer jwx.Signer) string {
	cred := credential.VerifiableCredential{
		ID:           uuid.NewString(),
		Context:      []any{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       signer.ID,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":            "did:example:123",
			"favoriteColor": "green",
			"favoriteFood":  "pizza",
		},
	}

	signed, err := SignVerifiableCredentialJWT(signer, cred)
	require.NoError(t, err)
	require.NotEmpty(t, signed)
	return string(signed)
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

func TestVerifyJWTPresentation(t *testing.T) {
	t.Run("empty presentation", func(tt *testing.T) {
		_, err := VerifyJWTPresentation(context.Background(), "", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "presentation cannot be empty")
	})

	t.Run("empty resolution", func(tt *testing.T) {
		_, err := VerifyJWTPresentation(context.Background(), "not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolution cannot be empty")
	})

	t.Run("invalid presentation", func(tt *testing.T) {
		r, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, err = VerifyJWTPresentation(context.Background(), "not-empty", r)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})

	t.Run("valid presentation, not signed by DID", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner("test-id", nil, privKey)
		assert.NoError(tt, err)

		jwtPres := getTestJWTPresentation(tt, *signer)
		_, err = VerifyJWTPresentation(context.Background(), jwtPres, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting issuer DID<test-id> to verify presentation")
	})

	t.Run("valid presentation, signed by DID the resolution can't resolve", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{web.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTPresentation(tt, *signer)
		_, err = VerifyJWTPresentation(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: key")
	})

	t.Run("valid presentation, kid not found", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner(didKey.String(), nil, privKey)
		assert.NoError(tt, err)

		jwtPres := getTestJWTPresentation(tt, *signer)
		_, err = VerifyJWTPresentation(context.Background(), jwtPres, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no verification methods with kid: ")
	})

	t.Run("valid presentation, bad signature", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtPres := getTestJWTPresentation(tt, *signer)

		// modify the signature to make it invalid
		jwtPres = jwtPres[:len(jwtPres)-5] + "baddata"

		verified, err := VerifyJWTPresentation(context.Background(), jwtPres, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "verifying JWT: could not verify message using any of the signatures or keys")
		assert.False(tt, verified)
	})

	t.Run("valid presentation, no credential", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtPres := geTestJWTPresentationNoCred(tt, *signer)

		verified, err := VerifyJWTPresentation(context.Background(), jwtPres, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})

	t.Run("mytests", func(t *testing.T) {
		_, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(t, err)
		assert.Contains(t, didKey.String(), "did:key:z6Mk")
	})

	t.Run("valid presentation, bad credential", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtPres := getTestJWTPresentationBadCred(tt, *signer)

		verified, err := VerifyJWTPresentation(context.Background(), jwtPres, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "verifying credential 0: parsing JWT: parsing credential token")
		assert.False(tt, verified)
	})

	t.Run("valid presentation", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
		assert.NoError(tt, err)

		jwtPres := getTestJWTPresentation(tt, *signer)
		verified, err := VerifyJWTPresentation(context.Background(), jwtPres, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
}

// cred status is a control flag. 0 = bad cred, 1 = good cred, 2 = no cred
func getTestJWTPresentation(t *testing.T, signer jwx.Signer) string {
	cred := credential.VerifiableCredential{
		ID:           uuid.NewString(),
		Context:      []any{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       signer.ID,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":            "did:example:123",
			"favoriteColor": "green",
			"favoriteFood":  "pizza",
		},
	}

	signedCred, err := SignVerifiableCredentialJWT(signer, cred)
	require.NoError(t, err)
	require.NotEmpty(t, signedCred)

	pres := credential.VerifiablePresentation{
		Context:              []any{"https://www.w3.org/2018/credentials/v1"},
		Type:                 []string{"VerifiablePresentation"},
		Holder:               signer.ID,
		VerifiableCredential: []any{string(signedCred)},
	}

	signedPres, err := SignVerifiablePresentationJWT(signer, nil, pres)
	require.NoError(t, err)
	return string(signedPres)
}

func getTestJWTPresentationBadCred(t *testing.T, signer jwx.Signer) string {
	cred := credential.VerifiableCredential{
		ID:           uuid.NewString(),
		Context:      []any{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       signer.ID,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":            "did:example:123",
			"favoriteColor": "green",
			"favoriteFood":  "pizza",
		},
	}

	signedCred, err := SignVerifiableCredentialJWT(signer, cred)
	require.NoError(t, err)
	require.NotEmpty(t, signedCred)

	// modify the signature to make it invalid
	signedCred = signedCred[:len(signedCred)-25]

	pres := credential.VerifiablePresentation{
		Context:              []any{"https://www.w3.org/2018/credentials/v1"},
		Type:                 []string{"VerifiablePresentation"},
		Holder:               signer.ID,
		VerifiableCredential: []any{string(signedCred)},
	}

	signedPres, err := SignVerifiablePresentationJWT(signer, nil, pres)
	require.NoError(t, err)
	return string(signedPres)
}

func geTestJWTPresentationNoCred(t *testing.T, signer jwx.Signer) string {
	pres := credential.VerifiablePresentation{
		Context: []any{"https://www.w3.org/2018/credentials/v1"},
		Type:    []string{"VerifiablePresentation"},
		Holder:  signer.ID,
	}

	signedPres, err := SignVerifiablePresentationJWT(signer, nil, pres)
	require.NoError(t, err)
	return string(signedPres)
}
