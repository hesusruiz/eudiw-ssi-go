package cryptosuite

import (
	gocrypto "crypto"
	"embed"

	"github.com/goccy/go-json"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	. "github.com/hesusruiz/eudiw-ssi-go/util"
)

var (
	//go:embed context
	knownContexts embed.FS
)

// CryptoSuite encapsulates the behavior of a proof type as per the W3C specification
// on data integrity https://w3c-ccg.github.io/data-integrity-spec/#creating-new-proof-types
type CryptoSuite interface {
	CryptoSuiteInfo

	// Sign https://w3c-ccg.github.io/data-integrity-spec/#proof-algorithm
	// this method mutates the provided provable object, adding a `proof` block`
	Sign(s Signer, p WithEmbeddedProof) error
	// Verify https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
	Verify(v Verifier, p WithEmbeddedProof) error
}

type CryptoSuiteInfo interface {
	ID() string
	Type() LDKeyType
	CanonicalizationAlgorithm() string
	MessageDigestAlgorithm() gocrypto.Hash
	SignatureAlgorithm() SignatureType
	RequiredContexts() []string
}

// CryptoSuiteProofType is an interface that defines functionality needed to sign and verify data
// It encapsulates the functionality defined by the data integrity proof type specification
// https://www.w3.org/community/reports/credentials/CG-FINAL-data-integrity-20220722/#creating-new-proof-types
type CryptoSuiteProofType interface {
	Marshal(data any) ([]byte, error)
	Canonicalize(marshaled []byte) (*string, error)
	// CreateVerifyHash https://www.w3.org/community/reports/credentials/CG-FINAL-data-integrity-20220722/#create-verify-hash-algorithm
	CreateVerifyHash(doc map[string]any, proof crypto.Proof, proofOptions *ProofOptions) ([]byte, error)
	// Digest runs a given digest algorithm https://www.w3.org/community/reports/credentials/CG-FINAL-data-integrity-20220722/#dfn-message-digest-algorithm
	// on a canonizliaed document prior to signing. Sometimes implementations will be a no-op as digesting is handled
	// by the signature algorithm itself.
	Digest(tbd []byte) ([]byte, error)
}

// WithEmbeddedProof is an interface that defines functionality needed to get/set proofs on objects with embedded proofs
type WithEmbeddedProof interface {
	GetProof() *crypto.Proof
	SetProof(p *crypto.Proof)
}

type Signer interface {
	Sign(tbs []byte) ([]byte, error)

	GetKeyID() string
	GetSignatureType() SignatureType
	GetSigningAlgorithm() string

	SetProofPurpose(purpose ProofPurpose)
	GetProofPurpose() ProofPurpose

	SetPayloadFormat(format PayloadFormat)
	GetPayloadFormat() PayloadFormat
}

type Verifier interface {
	Verify(message, signature []byte) error
	GetKeyID() string
}

type ProofOptions struct {
	// JSON-LD contexts to add to the proof
	Contexts []any

	// Indexes of the credential subject to require be revealed in BBS+ signatures
	RevealIndexes []int
}

// GenericProvable represents a provable that is not constrained by a specific type
type GenericProvable map[string]any

func (g *GenericProvable) GetProof() *crypto.Proof {
	if g == nil {
		return nil
	}
	provable := *g
	proof, gotProof := provable["proof"]
	if !gotProof {
		return nil
	}
	p := crypto.Proof(proof)
	return &p
}

func (g *GenericProvable) SetProof(p *crypto.Proof) {
	if g == nil {
		return
	}
	provable := *g
	provable["proof"] = p
	*g = provable
}

// GetContextsFromProvable searches from a Linked Data `@context` property in the document and returns the value
// associated with the context, if it exists.
func GetContextsFromProvable(p WithEmbeddedProof) ([]any, error) {
	provableBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var genericProvable map[string]any
	if err := json.Unmarshal(provableBytes, &genericProvable); err != nil {
		return nil, err
	}
	contexts, ok := genericProvable["@context"]
	if !ok {
		return nil, nil
	}
	interfaceContexts, err := InterfaceToInterfaceArray(contexts)
	if err != nil {
		return nil, err
	}
	return interfaceContexts, nil
}

// EnsureRequiredContexts attempt to verify that string context(s) exist in the context interface
func EnsureRequiredContexts(context []any, requiredContexts []string) []any {
	required := make(map[string]bool)
	for _, v := range requiredContexts {
		required[v] = true
	}

	for _, v := range context {
		vStr, ok := v.(string)
		// if it's a string, check to see if it's required
		if ok {
			req, ok := required[vStr]
			// if it's required and has a true value, we can check it off
			if ok && req {
				required[vStr] = false
			}
		}
	}

	// for all remaining true values, add it to the result
	for k, v := range required {
		if v {
			context = append(context, k)
		}
	}
	return context
}

func getKnownContext(fileName string) (string, error) {
	b, err := knownContexts.ReadFile("context/" + fileName)
	return string(b), err
}
