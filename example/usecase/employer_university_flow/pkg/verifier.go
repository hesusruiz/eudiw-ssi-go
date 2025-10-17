package pkg

import (
	"context"

	"github.com/hesusruiz/eudiw-ssi-go/credential/integrity"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"

	"github.com/pkg/errors"
)

// ValidateAccess is a very simple validation process against a Presentation Submission
// It checks:
// 1. That the VP is valid
// 2. All VCs in the VP are valid
// 3. That the VC was issued by a trusted entity (implied by the presentation, according to the Presentation Definition)
func ValidateAccess(verifier jwx.Verifier, r resolution.Resolver, submissionBytes []byte) error {
	_, _, vp, err := integrity.VerifyVerifiablePresentationJWT(context.Background(), verifier, r, string(submissionBytes))
	if err != nil {
		return errors.Wrap(err, "validating VP signature")
	}

	if err = vp.IsValid(); err != nil {
		return errors.Wrap(err, "validating VP")
	}
	return nil
}
