package peer

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/hesusruiz/eudiw-ssi-go/did"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"
)

type Resolver struct{}

var _ resolution.Resolver = (*Resolver)(nil)

func (Resolver) Resolve(_ context.Context, id string, opts ...resolution.Option) (*resolution.Result, error) {
	if !strings.HasPrefix(id, DIDPeerPrefix) {
		return nil, fmt.Errorf("not a did:peer DID: %s", id)
	}

	didPeer := DIDPeer(id)
	if len(didPeer) < len(DIDPeerPrefix)+2 {
		return nil, errors.New("did is too short")
	}

	m := string(didPeer[9])
	if peerMethodAvailable(m) {
		switch m {
		case "0":
			return Method0{}.resolve(didPeer, opts)
		case "1":
			return Method1{}.resolve(didPeer, opts)
		case "2":
			return Method2{}.resolve(didPeer, opts)
		default:
			return nil, fmt.Errorf("%s method not supported", m)
		}
	}
	return nil, fmt.Errorf("could not resolve peer DID: %s", id)
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.PeerMethod}
}
