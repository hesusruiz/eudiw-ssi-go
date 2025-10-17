package pkh

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

func (Resolver) Resolve(_ context.Context, id string, _ ...resolution.Option) (*resolution.Result, error) {
	if !strings.HasPrefix(id, DIDPKHPrefix) {
		return nil, fmt.Errorf("not a did:pkh DID: %s", id)
	}
	didPKH := PKH(id)
	doc, err := didPKH.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:pkh DID: %s", id)
	}
	return &resolution.Result{Document: *doc}, nil
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.PKHMethod}
}
