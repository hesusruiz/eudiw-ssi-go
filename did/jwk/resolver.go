package jwk

import (
	"context"

	"github.com/pkg/errors"

	"github.com/hesusruiz/eudiw-ssi-go/did"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"
)

type Resolver struct{}

var _ resolution.Resolver = (*Resolver)(nil)

func (Resolver) Resolve(_ context.Context, id string, _ ...resolution.Option) (*resolution.Result, error) {
	didJWK := JWK(id)
	doc, err := didJWK.Expand()
	if err != nil {
		return nil, errors.Wrap(err, "expanding did:jwk")
	}
	return &resolution.Result{Document: *doc}, nil
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.JWKMethod}
}
