package peer

import (
	gocrypto "crypto"

	"github.com/pkg/errors"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/did"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"
	"github.com/hesusruiz/eudiw-ssi-go/util"
)

// Method0 Method 0: inception key without doc
// https://identity.foundation/peer-did-method-spec/index.html#generation-method
// The DID doc offers no endpoint. This makes the DID functionally equivalent to a did:key value For example,
// did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH is equivalent to
// did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
type Method0 struct {
	kt crypto.KeyType
}

func (Method0) Method() did.Method {
	return did.PeerMethod
}

func (Method0) Generate(kt crypto.KeyType, publicKey gocrypto.PublicKey) (*DIDPeer, error) {
	var didPeer DIDPeer
	encoded, err := encodePublicKeyWithKeyMultiCodecType(kt, publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "encoding public key for did:peer")
	}
	didPeer = buildDIDPeerFromEncoded(0, encoded)
	return &didPeer, err
}

// Resolve resolves a did:peer into a DID Document
// To do so, it decodes the key, constructs a verification method, and returns a DID Document .This allows Method0
// to implement the DID Resolver interface and be used to expand the did into the DID Document.
func (Method0) resolve(didDoc did.DID, _ resolution.Option) (*resolution.Result, error) {
	d, ok := didDoc.(DIDPeer)
	if !ok {
		return nil, errors.Wrap(util.CastingError, "did:peer")
	}

	v, err := d.Suffix()
	if err != nil {
		return nil, err
	}

	pubKey, _, cryptoKeyType, err := did.DecodeMultibaseEncodedKey(v)
	if err != nil {
		return nil, err
	}

	keyReference := Hash + v
	id := string(d)

	verificationMethod, err := did.ConstructJWKVerificationMethod(keyReference, id, pubKey, cryptoKeyType)
	if err != nil {
		return nil, err
	}

	verificationMethodSet := []did.VerificationMethodSet{[]string{keyReference}}
	document := did.Document{
		Context:              did.KnownDIDContext,
		ID:                   id,
		VerificationMethod:   []did.VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		KeyAgreement:         verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
	}
	return &resolution.Result{Document: document}, nil
}
