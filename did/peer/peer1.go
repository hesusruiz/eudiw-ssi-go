package peer

import (
	"github.com/hesusruiz/eudiw-ssi-go/did"
	"github.com/hesusruiz/eudiw-ssi-go/util"
)

// Method1 Method 1: genesis doc
type Method1 struct{}

func (Method1) Method() did.Method {
	return did.PeerMethod
}

// Generate https://identity.foundation/peer-did-method-spec/#generation-method
// Creates a genesis version of JSON text of the DID doc for the DID. This inception key is the key that creates the
// DID and authenticates when exchanging it with the first peer CANNOT include the DID itself This lets the doc be
// created without knowing the DID's value in advance. Suppressing the DID value creates a stored variant of peer DID
// doc data, as opposed to the resolved variant that would have an actual DID value in the root id property. (In either
// the stored or resolved variant of the doc, anywhere else that the DID value would appear, it should appear as a
// relative reference rather than an absolute value. For example, each controller property of a verificationMethod
// that is owned by this DID would say "controller": "#id".). Calculate the SHA256 [RFC4634] hash of the bytes of
// the stored variant of the genesis version of the DID doc, and make this value the new DID's numeric basis.
func (Method1) Generate() (*DIDPeer, error) {
	// Create a Genesis Version
	// TODO support method 1 https://github.com/hesusruiz/eudiw-ssi-go/issues/137
	return nil, util.NotImplementedError
}
