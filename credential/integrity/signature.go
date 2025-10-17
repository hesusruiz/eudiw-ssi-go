package integrity

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hesusruiz/eudiw-ssi-go/credential"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/did"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"

	"github.com/pkg/errors"
)

// VerifyCredentialSignature verifies the signature of a credential of any type
// TODO(gabe) support other types of credentials https://github.com/hesusruiz/eudiw-ssi-go/issues/352
func VerifyCredentialSignature(ctx context.Context, genericCred any, r resolution.Resolver) (bool, error) {
	if genericCred == nil {
		return false, errors.New("credential cannot be empty")
	}
	if r == nil {
		return false, errors.New("resolution cannot be empty")
	}
	switch typedCred := genericCred.(type) {
	case map[string]any:
		typedCredBytes, err := json.Marshal(typedCred)
		if err != nil {
			return false, errors.Wrap(err, "marshalling credential map")
		}
		var cred credential.VerifiableCredential
		if err = json.Unmarshal(typedCredBytes, &cred); err != nil {
			return false, errors.Wrap(err, "unmarshalling credential object")
		}
		if cred.IsEmpty() {
			return false, errors.New("map is not a valid credential")
		}
		return VerifyCredentialSignature(ctx, cred, r)
	case *credential.VerifiableCredential:
		return VerifyDataIntegrityCredential(ctx, *typedCred, r)
	case credential.VerifiableCredential:
		return VerifyDataIntegrityCredential(ctx, typedCred, r)
	case []byte:
		// turn it into a string and try again
		return VerifyCredentialSignature(ctx, string(typedCred), r)
	case string:
		// could be a Data Integrity credential
		var cred credential.VerifiableCredential
		if err := json.Unmarshal([]byte(typedCred), &cred); err == nil {
			return VerifyCredentialSignature(ctx, cred, r)
		}

		// could be a JWT
		return VerifyJWTCredential(ctx, typedCred, r)
	}
	return false, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// VerifyJWTCredential verifies the signature of a JWT credential after parsing it to resolve the issuer DID
// The issuer DID is resolution from the provided resolution, and used to find the issuer's public key matching
// the KID in the JWT header.
func VerifyJWTCredential(ctx context.Context, cred string, r resolution.Resolver) (bool, error) {
	if cred == "" {
		return false, errors.New("credential cannot be empty")
	}
	if r == nil {
		return false, errors.New("resolution cannot be empty")
	}
	headers, token, _, err := ParseVerifiableCredentialFromJWT(cred)
	if err != nil {
		return false, errors.Wrap(err, "parsing JWT")
	}

	// get key to verify the credential with
	issuerKID := headers.KeyID()
	if issuerKID == "" {
		return false, errors.Errorf("missing kid in header of credential<%s>", token.JwtID())
	}
	issuerDID, err := r.Resolve(ctx, token.Issuer())
	if err != nil {
		return false, errors.Wrapf(err, "error getting issuer DID<%s> to verify credential<%s>", token.Issuer(), token.JwtID())
	}
	issuerKey, err := did.GetKeyFromVerificationMethod(issuerDID.Document, issuerKID)
	if err != nil {
		return false, errors.Wrapf(err, "error getting key to verify credential<%s>", token.JwtID())
	}

	// construct a verifier
	credVerifier, err := jwx.NewJWXVerifier(issuerDID.ID, &issuerKID, issuerKey)
	if err != nil {
		return false, errors.Wrapf(err, "error constructing verifier for credential<%s>", token.JwtID())
	}
	// verify the signature
	if _, _, _, err = VerifyVerifiableCredentialJWT(*credVerifier, cred); err != nil {
		return false, errors.Wrapf(err, "error verifying credential<%s>", token.JwtID())
	}
	return true, nil
}

// VerifyDataIntegrityCredential verifies the signature of a Data Integrity credential
// TODO(gabe): https://github.com/hesusruiz/eudiw-ssi-go/issues/196
func VerifyDataIntegrityCredential(_ context.Context, cred credential.VerifiableCredential, _ resolution.Resolver) (bool, error) {
	if cred.IsEmpty() {
		return false, errors.New("credential cannot be empty")
	}
	if cred.GetProof() == nil {
		return false, errors.New("credential must have a proof")
	}

	return false, errors.New("not implemented")
}

// VerifyJWTPresentation verifies the signature of a JWT presentation after parsing it to resolve the issuer DID
// The issuer DID is resolution from the provided resolution, and used to find the issuer's public key matching
// the KID in the JWT header.
func VerifyJWTPresentation(ctx context.Context, pres string, r resolution.Resolver) (bool, error) {
	if pres == "" {
		return false, errors.New("presentation cannot be empty")
	}
	if r == nil {
		return false, errors.New("resolution cannot be empty")
	}
	headers, token, _, err := ParseVerifiablePresentationFromJWT(pres)
	if err != nil {
		return false, errors.Wrap(err, "parsing JWT")
	}

	// get key to verify the presentation with
	issuerKID := headers.KeyID()
	if issuerKID == "" {
		return false, errors.Errorf("missing kid in header of presentation<%s>", token.JwtID())
	}
	issuerDID, err := r.Resolve(ctx, token.Issuer())
	if err != nil {
		return false, errors.Wrapf(err, "error getting issuer DID<%s> to verify presentation<%s>", token.Issuer(), token.JwtID())
	}
	issuerKey, err := did.GetKeyFromVerificationMethod(issuerDID.Document, issuerKID)
	if err != nil {
		return false, errors.Wrapf(err, "error getting key to verify presentation<%s>", token.JwtID())
	}

	// construct a verifier
	presVerifier, err := jwx.NewJWXVerifier(issuerDID.ID, &issuerKID, issuerKey)
	if err != nil {
		return false, errors.Wrapf(err, "error constructing verifier for presentation<%s>", token.JwtID())
	}
	// verify the signature
	if _, _, _, err = VerifyVerifiablePresentationJWT(ctx, *presVerifier, r, pres); err != nil {
		return false, errors.Wrapf(err, "error verifying presentation<%s>", token.JwtID())
	}

	return true, nil
}
