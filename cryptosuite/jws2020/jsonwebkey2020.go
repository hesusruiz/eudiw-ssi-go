package jws2020

import (
	gocrypto "crypto"
	"fmt"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite"
	"github.com/hesusruiz/eudiw-ssi-go/util"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/pkg/errors"
)

type (
	KTY string
	CRV string
	ALG string
)

const (
	// Supported key types

	OKP KTY = "OKP"
	EC  KTY = "EC"
	RSA KTY = "RSA"

	// Supported curves

	Ed25519   CRV = "Ed25519"
	X25519    CRV = "X25519"
	SECP256k1 CRV = "secp256k1"
	P256      CRV = "P-256"
	P384      CRV = "P-384"
)

// JSONWebKey2020 complies with https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020
type JSONWebKey2020 struct {
	ID                string                `json:"id,omitempty"`
	Type              cryptosuite.LDKeyType `json:"type,omitempty"`
	Controller        string                `json:"controller,omitempty"`
	jwx.PrivateKeyJWK `json:"privateKeyJwk,omitempty"`
	jwx.PublicKeyJWK  `json:"publicKeyJwk,omitempty"`
}

func (jwk *JSONWebKey2020) IsValid() error {
	return util.NewValidator().Struct(jwk)
}

// GenerateJSONWebKey2020 The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
// these pairs are supported in this library and generated via the function below
// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
func GenerateJSONWebKey2020(kty KTY, crv CRV) (*JSONWebKey2020, error) {
	if kty == RSA {
		if crv != "" {
			return nil, fmt.Errorf("RSA key type cannot have curve specified: %s", crv)
		}
		return GenerateRSAJSONWebKey2020()
	}
	if crv == "" {
		return nil, errors.New("crv must be specified for non-RSA key types")
	}
	if kty == OKP {
		switch crv {
		case Ed25519:
			return GenerateEd25519JSONWebKey2020()
		case X25519:
			return GenerateX25519JSONWebKey2020()
		default:
			return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
		}
	}
	if kty == EC {
		switch crv {
		case SECP256k1:
			return GenerateSECP256k1JSONWebKey2020()
		case P256:
			return GenerateP256JSONWebKey2020()
		case P384:
			return GenerateP384JSONWebKey2020()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", crv)
		}
	}
	return nil, fmt.Errorf("unsupported key type: %s", kty)
}

// JSONWebKey2020FromPrivateKey returns a JsonWebKey2020 value from a given private key, containing both JWK
// public and private key representations of the key.
func JSONWebKey2020FromPrivateKey(key gocrypto.PrivateKey) (*JSONWebKey2020, error) {
	pubKeyJWK, privKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nil, key)
	if err != nil {
		return nil, err
	}
	return &JSONWebKey2020{
		Type:          cryptosuite.JSONWebKey2020Type,
		PrivateKeyJWK: *privKeyJWK,
		PublicKeyJWK:  *pubKeyJWK,
	}, nil
}

// GenerateRSAJSONWebKey2020 returns a JsonWebKey2020 value, containing both public and private keys
// for an RSA-2048 key.
func GenerateRSAJSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateRSA2048Key()
	if err != nil {
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateEd25519JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for an Ed25519 key.
func GenerateEd25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateEd25519Key()
	if err != nil {
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateX25519JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for an Ed25519 key transformed to a bi-rationally equivalent X25519 key.
func GenerateX25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateSECP256k1JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a secp256k1 key transformed to an ecdsa key.
// We use the secp256k1 implementation from Decred https://github.com/decred/dcrd
// which is utilized in the widely accepted go bitcoin node implementation from the btcsuite project
// https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go#L23
func GenerateSECP256k1JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating secp256k1 key")
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateP256JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a P-256 ECDSA key.
func GenerateP256JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateP256Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating p-256 key")
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateP384JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a P-384 ECDSA key.
func GenerateP384JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateP384Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating p-384 key")
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// JSONWebKeySigner constructs a signer for a JSONWebKey2020 object.
// Given a signature algorithm (e.g. ES256, PS384) and a JSON Web Key (private key), the signer is able to accept
// a message and provide a valid JSON Web Signature (JWS) value as a result.
type JSONWebKeySigner struct {
	jwx.Signer
	purpose cryptosuite.ProofPurpose
	format  cryptosuite.PayloadFormat
}

// Sign returns a byte array signature value for a message `tbs`
func (s *JSONWebKeySigner) Sign(tbs []byte) ([]byte, error) {
	b64 := "b64"
	headers := jws.NewHeaders()
	if err := headers.Set(b64, false); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.CriticalKey, []string{b64}); err != nil {
		return nil, err
	}
	// Ed25519 is not supported by the jwx library yet https://github.com/hesusruiz/eudiw-ssi-go/issues/520
	alg := s.ALG
	if alg == "Ed25519" {
		alg = jwa.EdDSA.String()
	}
	return jws.Sign(nil, jws.WithKey(jwa.SignatureAlgorithm(alg), s.PrivateKey), jws.WithHeaders(headers), jws.WithDetachedPayload(tbs))
}

func (s *JSONWebKeySigner) GetKeyID() string {
	return s.KID
}

func (*JSONWebKeySigner) GetSignatureType() cryptosuite.SignatureType {
	return JSONWebSignature2020
}

func (s *JSONWebKeySigner) GetSigningAlgorithm() string {
	return s.ALG
}

func (s *JSONWebKeySigner) SetProofPurpose(purpose cryptosuite.ProofPurpose) {
	s.purpose = purpose
}

func (s *JSONWebKeySigner) GetProofPurpose() cryptosuite.ProofPurpose {
	return s.purpose
}

func (s *JSONWebKeySigner) SetPayloadFormat(format cryptosuite.PayloadFormat) {
	s.format = format
}

func (s *JSONWebKeySigner) GetPayloadFormat() cryptosuite.PayloadFormat {
	return s.format
}

func NewJSONWebKeySigner(id string, key jwx.PrivateKeyJWK, purpose cryptosuite.ProofPurpose) (*JSONWebKeySigner, error) {
	signer, err := jwx.NewJWXSignerFromJWK(id, key)
	if err != nil {
		return nil, err
	}
	return &JSONWebKeySigner{
		Signer:  *signer,
		purpose: purpose,
	}, nil
}

// JSONWebKeyVerifier constructs a verifier for a JSONWebKey2020 object.
// Given a signature algorithm (e.g. ES256, PS384) and a JSON Web Key (pub key), the verifier is able to accept
// a message and signature, and provide a result to whether the signature is valid.
type JSONWebKeyVerifier struct {
	jwx.Verifier
}

// Verify attempts to verify a `signature` against a given `message`, returning nil if the verification is successful
// and an error should it fail.
func (v JSONWebKeyVerifier) Verify(message, signature []byte) error {
	pubKey, err := v.PublicKeyJWK.ToPublicKey()
	if err != nil {
		return errors.Wrap(err, "getting public key")
	}
	// Ed25519 is not supported by the jwx library yet https://github.com/hesusruiz/eudiw-ssi-go/issues/520
	alg := v.ALG
	if alg == "Ed25519" {
		alg = jwa.EdDSA.String()
	}
	_, err = jws.Verify(signature, jws.WithKey(jwa.SignatureAlgorithm(alg), pubKey), jws.WithDetachedPayload(message))
	return err
}

func (v JSONWebKeyVerifier) GetKeyID() string {
	return v.KID
}

func NewJSONWebKeyVerifier(id string, key jwx.PublicKeyJWK) (*JSONWebKeyVerifier, error) {
	verifier, err := jwx.NewJWXVerifierFromJWK(id, key)
	if err != nil {
		return nil, err
	}
	return &JSONWebKeyVerifier{Verifier: *verifier}, nil
}

// PubKeyBytesToTypedKey converts a public key byte slice to a crypto.PublicKey based on a given key type, merging
// both LD key types and JWK key types
func PubKeyBytesToTypedKey(keyBytes []byte, kt cryptosuite.LDKeyType) (gocrypto.PublicKey, error) {
	var convertedKeyType crypto.KeyType
	switch kt.String() {
	case cryptosuite.JSONWebKey2020Type.String():
		// we cannot know this key type based on the bytes alone
		return keyBytes, nil
	case crypto.Ed25519.String(), cryptosuite.Ed25519VerificationKey2018.String(), cryptosuite.Ed25519VerificationKey2020.String():
		convertedKeyType = crypto.Ed25519
	case crypto.X25519.String(), cryptosuite.X25519KeyAgreementKey2019.String(), cryptosuite.X25519KeyAgreementKey2020.String():
		convertedKeyType = crypto.X25519
	case crypto.SECP256k1.String(), cryptosuite.ECDSASECP256k1VerificationKey2019.String():
		convertedKeyType = crypto.SECP256k1
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
	return crypto.BytesToPubKey(keyBytes, convertedKeyType)
}
