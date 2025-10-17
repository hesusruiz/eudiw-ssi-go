package did

import (
	"fmt"
	"reflect"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/multiformats/go-multibase"

	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite"
	"github.com/hesusruiz/eudiw-ssi-go/util"
)

const (
	KnownDIDContext string = "https://www.w3.org/ns/did/v1"

	// Base58BTCMultiBase Base58BTC https://github.com/multiformats/go-multibase/blob/master/multibase.go
	Base58BTCMultiBase = multibase.Base58BTC
)

// Document is a representation of the did core specification https://www.w3.org/TR/did-core
// TODO(gabe) enforce validation of DID syntax https://www.w3.org/TR/did-core/#did-syntax
type Document struct {
	Context any `json:"@context,omitempty"`
	// As per https://www.w3.org/TR/did-core/#did-subject intermediate representations of DID Documents do not
	// require an ID property. The provided test vectors demonstrate IRs. As such, the property is optional.
	ID                   string                  `json:"id,omitempty"`
	Controller           any                     `json:"controller,omitempty"`
	AlsoKnownAs          any                     `json:"alsoKnownAs,omitempty"`
	VerificationMethod   []VerificationMethod    `json:"verificationMethod,omitempty" validate:"dive"`
	Authentication       []VerificationMethodSet `json:"authentication,omitempty" validate:"dive"`
	AssertionMethod      []VerificationMethodSet `json:"assertionMethod,omitempty" validate:"dive"`
	KeyAgreement         []VerificationMethodSet `json:"keyAgreement,omitempty" validate:"dive"`
	CapabilityInvocation []VerificationMethodSet `json:"capabilityInvocation,omitempty" validate:"dive"`
	CapabilityDelegation []VerificationMethodSet `json:"capabilityDelegation,omitempty" validate:"dive"`
	Services             []Service               `json:"service,omitempty" validate:"dive"`
}

type VerificationMethod struct {
	ID              string                `json:"id" validate:"required"`
	Type            cryptosuite.LDKeyType `json:"type" validate:"required"`
	Controller      string                `json:"controller" validate:"required"`
	PublicKeyBase58 string                `json:"publicKeyBase58,omitempty"`
	// must conform to https://datatracker.ietf.org/doc/html/rfc7517
	PublicKeyJWK *jwx.PublicKeyJWK `json:"publicKeyJwk,omitempty" validate:"omitempty"`
	// https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
	// for PKH DIDs - https://github.com/w3c-ccg/did-pkh/blob/90b28ad3c18d63822a8aab3c752302aa64fc9382/did-pkh-method-draft.md
	BlockchainAccountID string `json:"blockchainAccountId,omitempty"`
}

// VerificationMethodSet is a union type supporting the `authentication`, `assertionMethod`, `keyAgreement`,
// `capabilityInvocation`, and `capabilityDelegation` types.
// A set of one or more verification methods. Each verification method MAY be embedded or referenced.
// TODO(gabe) consider changing this to a custom unmarshaler https://stackoverflow.com/a/28016508
type VerificationMethodSet any

// Service is a property compliant with the did-core spec https://www.w3.org/TR/did-core/#services
type Service struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
	// A string, map, or set composed of one or more strings and/or maps
	// All string values must be valid URIs
	ServiceEndpoint any      `json:"serviceEndpoint" validate:"required"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
	Accept          []string `json:"accept,omitempty"`
	Sig             any      `json:"sig,omitempty"`
	Enc             any      `json:"enc,omitempty"`
}

func (s *Service) IsValid() bool {
	return util.NewValidator().Struct(s) == nil
}

func (d *Document) IsEmpty() bool {
	if d == nil {
		return true
	}
	return reflect.DeepEqual(d, &Document{})
}

func (d *Document) IsValid() error {
	return util.NewValidator().Struct(d)
}

// KeyTypeToMultikeyLDType converts crypto.KeyType to cryptosuite.LDKeyType for non JWKs
func KeyTypeToMultikeyLDType(kt crypto.KeyType) (cryptosuite.LDKeyType, error) {
	switch kt {
	case crypto.Ed25519:
		return cryptosuite.Ed25519VerificationKey2020, nil
	case crypto.X25519:
		return cryptosuite.X25519KeyAgreementKey2020, nil
	case crypto.SECP256k1:
		return cryptosuite.ECDSASECP256k1VerificationKey2019, nil
	case crypto.P256:
		return cryptosuite.P256Key2021, nil
	case crypto.P384:
		return cryptosuite.P384Key2021, nil
	case crypto.P521:
		return cryptosuite.P521Key2021, nil
	case crypto.BLS12381G1:
		return cryptosuite.BLS12381G1Key2020, nil
	case crypto.BLS12381G2:
		return cryptosuite.BLS12381G2Key2020, nil
	default:
		return "", fmt.Errorf("keyType %+v failed to convert to multikey LDKeyType", kt)
	}
}

type PublicKeyPurpose string

const (
	Authentication       PublicKeyPurpose = "authentication"
	AssertionMethod      PublicKeyPurpose = "assertionMethod"
	CapabilityInvocation PublicKeyPurpose = "capabilityInvocation"
	CapabilityDelegation PublicKeyPurpose = "capabilityDelegation"
	KeyAgreement         PublicKeyPurpose = "keyAgreement"
)
