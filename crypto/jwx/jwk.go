package jwx

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/pkg/errors"
)

const (
	DilithiumKTY = "LWE"
)

// PrivateKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PrivateKeyJWK struct {
	KTY    string `json:"kty,omitempty" validate:"required"`
	CRV    string `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Use    string `json:"use,omitempty"`
	KeyOps string `json:"key_ops,omitempty"`
	ALG    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
	D      string `json:"d,omitempty"`
	DP     string `json:"dp,omitempty"`
	DQ     string `json:"dq,omitempty"`
	P      string `json:"p,omitempty"`
	Q      string `json:"q,omitempty"`
	QI     string `json:"qi,omitempty"`
}

func (k *PrivateKeyJWK) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &PrivateKeyJWK{})
}

// ToPublicKeyJWK converts a PrivateKeyJWK to a PublicKeyJWK
func (k *PrivateKeyJWK) ToPublicKeyJWK() PublicKeyJWK {
	if k.ALG == "" {
		alg, err := AlgFromKeyAndCurve(k.ALG, k.CRV)
		if err == nil {
			k.ALG = alg
		}
	}
	return PublicKeyJWK{
		KTY:    k.KTY,
		CRV:    k.CRV,
		X:      k.X,
		Y:      k.Y,
		N:      k.N,
		E:      k.E,
		Use:    k.Use,
		KeyOps: k.KeyOps,
		ALG:    k.ALG,
		KID:    k.KID,
	}
}

// ToPrivateKey converts a PrivateKeyJWK to a PrivateKeyJWK
func (k *PrivateKeyJWK) ToPrivateKey() (gocrypto.PrivateKey, error) {
	if k.ALG == "" {
		alg, err := AlgFromKeyAndCurve(k.KTY, k.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		// Ed25519 is not supported by the jwx library yet https://github.com/hesusruiz/eudiw-ssi-go/issues/520
		if alg == jwa.Ed25519.String() {
			alg = jwa.EdDSA.String()
		}
		k.ALG = alg
	}
	if IsSupportedJWXSigningVerificationAlgorithm(k.ALG) || IsSupportedKeyAgreementType(k.CRV) {
		return k.toSupportedPrivateKey()
	}
	return nil, fmt.Errorf("unsupported key conversion %+v", k)
}

func (k *PrivateKeyJWK) toSupportedPrivateKey() (gocrypto.PrivateKey, error) {
	keyBytes, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	gotJWK, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "creating JWK from private key")
	}
	var key gocrypto.PrivateKey
	if err = gotJWK.Raw(&key); err != nil {
		return nil, errors.Wrap(err, "converting JWK to go key")
	}

	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PrivateKey)
	}
	return key, nil
}

func (k *PrivateKeyJWK) toExperimentalPrivateKey() (gocrypto.PrivateKey, error) {
	switch k.KTY {
	default:
		return nil, fmt.Errorf("unsupported key type %s", k.KTY)
	}
}

// PublicKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PublicKeyJWK struct {
	KTY    string `json:"kty,omitempty" validate:"required"`
	CRV    string `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Use    string `json:"use,omitempty"`
	KeyOps string `json:"key_ops,omitempty"`
	ALG    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
}

func (k *PublicKeyJWK) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &PublicKeyJWK{})
}

// Thumbprint returns the JWK thumbprint using the indicated hashing algorithm (SHA-256), according to RFC 7638
// The thumbprint is returned as a base64URL encoded string.
func (k *PublicKeyJWK) Thumbprint() (string, error) {
	keyBytes, err := json.Marshal(k)
	if err != nil {
		return "", err
	}
	gotJWK, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return "", errors.Wrap(err, "creating JWK from public key")
	}
	thumbprintBytes, err := gotJWK.Thumbprint(gocrypto.SHA256)
	if err != nil {
		return "", errors.Wrap(err, "creating thumbprint")
	}
	return base64.RawURLEncoding.EncodeToString(thumbprintBytes), nil
}

// ToPublicKey converts a PublicKeyJWK to a PublicKey
func (k *PublicKeyJWK) ToPublicKey() (gocrypto.PublicKey, error) {
	if k.ALG == "" {
		alg, err := AlgFromKeyAndCurve(k.KTY, k.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		k.ALG = alg
	}

	if IsSupportedJWXSigningVerificationAlgorithm(k.ALG) || IsSupportedKeyAgreementType(k.CRV) {
		return k.toSupportedPublicKey()
	}
	return nil, fmt.Errorf("unsupported key conversion %+v", k)
}

func (k *PublicKeyJWK) toSupportedPublicKey() (gocrypto.PublicKey, error) {
	keyBytes, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	gotJWK, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "creating JWK from public key")
	}
	var key gocrypto.PublicKey
	if err = gotJWK.Raw(&key); err != nil {
		return nil, errors.Wrap(err, "converting JWK to go key")
	}

	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PublicKey)
	}
	return key, nil
}

func (k *PublicKeyJWK) toExperimentalPublicKey() (gocrypto.PublicKey, error) {
	switch k.KTY {
	default:
		return nil, fmt.Errorf("unsupported key type %s", k.KTY)
	}
}

// PublicKeyToPublicKeyJWK converts a public key to a PublicKeyJWK
func PublicKeyToPublicKeyJWK(kid *string, key gocrypto.PublicKey) (*PublicKeyJWK, error) {
	// dereference the ptr, which could be a nested ptr
	for reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PublicKey)
	}
	var pubKeyJWK *PublicKeyJWK
	var err error
	switch k := key.(type) {
	case rsa.PublicKey:
		pubKeyJWK, err = jwkFromRSAPublicKey(k)
	case ed25519.PublicKey:
		pubKeyJWK, err = jwkFromEd25519PublicKey(k)
	case x25519.PublicKey:
		pubKeyJWK, err = jwkFromX25519PublicKey(k)
	case secp256k1.PublicKey:
		pubKeyJWK, err = jwkFromSECP256k1PublicKey(k)
	case ecdsa.PublicKey:
		pubKeyJWK, err = jwkFromECDSAPublicKey(k)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	}
	if err != nil {
		return nil, err
	}
	if kid != nil {
		pubKeyJWK.KID = *kid
	}
	if pubKeyJWK.ALG == "" {
		alg, err := AlgFromKeyAndCurve(pubKeyJWK.KTY, pubKeyJWK.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		pubKeyJWK.ALG = alg
	}
	return pubKeyJWK, err
}

// PrivateKeyToPrivateKeyJWK converts a private key to a PrivateKeyJWK
func PrivateKeyToPrivateKeyJWK(keyID *string, key gocrypto.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	// dereference the ptr, which could be nested
	for reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PrivateKey)
	}
	var pubKeyJWK *PublicKeyJWK
	var privKeyJWK *PrivateKeyJWK
	var err error
	switch k := key.(type) {
	case rsa.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromRSAPrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
	case ed25519.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromEd25519PrivateKey(k)
	case x25519.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromX25519PrivateKey(k)
	case secp256k1.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromSECP256k1PrivateKey(k)
	case ecdsa.PrivateKey:
		if k.Curve == elliptic.P224() {
			return nil, nil, fmt.Errorf("unsupported curve: %s", k.Curve.Params().Name)
		}
		pubKeyJWK, privKeyJWK, err = jwkFromECDSAPrivateKey(k)
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", k)
	}
	if err != nil {
		return nil, nil, err
	}
	if keyID != nil {
		pubKeyJWK.KID = *keyID
		privKeyJWK.KID = *keyID
	}
	if privKeyJWK.ALG == "" {
		alg, err := AlgFromKeyAndCurve(privKeyJWK.KTY, privKeyJWK.CRV)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting alg from key and curve")
		}
		pubKeyJWK.ALG = alg
		privKeyJWK.ALG = alg
	}
	return pubKeyJWK, privKeyJWK, nil
}

// jwkFromRSAPrivateKey converts a RSA private key to a JWK
func jwkFromRSAPrivateKey(key rsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating rsa jwk")
	}
	rsaJWKBytes, err := json.Marshal(rsaJWKGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling rsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling rsa public jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling rsa private jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromRSAPublicKey converts an RSA public key to a JWK
func jwkFromRSAPublicKey(key rsa.PublicKey) (*PublicKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating rsa jwk")
	}
	if err = jwk.AssignKeyID(rsaJWKGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	rsaJWKBytes, err := json.Marshal(rsaJWKGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling rsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling rsa jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromEd25519PrivateKey converts an Ed25519 private key to a JWK
func jwkFromEd25519PrivateKey(key ed25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	if err = jwk.AssignKeyID(ed25519JWKGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	ed25519JWKBytes, err := json.Marshal(ed25519JWKGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ed25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(ed25519JWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkFromEd25519PublicKey(key ed25519.PublicKey) (*PublicKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	if err = jwk.AssignKeyID(ed25519JWKGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	x25519JWKBytes, err := json.Marshal(ed25519JWKGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromX25519PrivateKey converts a X25519 private key to a JWK
func jwkFromX25519PrivateKey(key x25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	x25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating x25519 jwk")
	}
	if err = jwk.AssignKeyID(x25519JWKGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	x25519JWKBytes, err := json.Marshal(x25519JWKGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromX25519PublicKey converts a X25519 public key to a JWK
func jwkFromX25519PublicKey(key x25519.PublicKey) (*PublicKeyJWK, error) {
	x25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating x25519 jwk")
	}
	if err = jwk.AssignKeyID(x25519JWKGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	x25519JWKBytes, err := json.Marshal(x25519JWKGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling x25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling x25519 jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromSECP256k1PrivateKey converts a SECP256k1 private key to a JWK
func jwkFromSECP256k1PrivateKey(key secp256k1.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaPrivKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	if err = jwk.AssignKeyID(secp256k1JWKGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	secp256k1JWKBytes, err := json.Marshal(secp256k1JWKGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling secp256k1 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(secp256k1JWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling secp256k1 public jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(secp256k1JWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling secp256k1 private jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkFromSECP256k1PublicKey(key secp256k1.PublicKey) (*PublicKeyJWK, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWK, err := jwk.FromRaw(ecdsaPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	if err = jwk.AssignKeyID(secp256k1JWK); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	secp256k1JWKBytes, err := json.Marshal(secp256k1JWK)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling secp256k1 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(secp256k1JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling secp256k1 jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkFromECDSAPrivateKey(key ecdsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	if err = jwk.AssignKeyID(ecdsaKeyGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	ecdsaKeyBytes, err := json.Marshal(ecdsaKeyGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling ecdsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ecdsa public jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ecdsa private jwk")
	}

	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkFromECDSAPublicKey(key ecdsa.PublicKey) (*PublicKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	if err = jwk.AssignKeyID(ecdsaKeyGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	ecdsaKeyBytes, err := json.Marshal(ecdsaKeyGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling ecdsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ecdsa jwk")
	}
	return &publicKeyJWK, nil
}
