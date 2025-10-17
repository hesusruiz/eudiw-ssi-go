package exchange

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/hesusruiz/eudiw-ssi-go/credential"
	"github.com/hesusruiz/eudiw-ssi-go/credential/integrity"
	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
)

// EmbedTarget describes where a presentation_submission is located in an object model
// https://identity.foundation/presentation-exchange/#embed-targets
type EmbedTarget string

const (
	// JWTVPTarget is an embed target where a presentation submission is represented alongside a Verifiable Presentation
	// in a JWT value. `presentation_submission` is a top-level claim alongside `vc` for the VP
	JWTVPTarget EmbedTarget = "jwt_vp"
	// JWTTarget   EmbedTarget = "jwt"
	// LDPVPTarget EmbedTarget = "ldp_vp"

	PresentationSubmissionContext string = "https://identity.foundation/presentation-exchange/submission/v1"
	PresentationSubmissionType    string = "PresentationSubmission"
)

// PresentationClaim 's may be of any claim format designation, including LD or JWT variations of VCs or VPs
// https://identity.foundation/presentation-exchange/#claim-format-designations
// This object must be constructed for each claim before processing of a Presentation Definition
type PresentationClaim struct {
	// Data Integrity Claim
	// If we have a Credential or Presentation value, we assume we have a LDP_VC or LDP_VP respectively
	Credential   *credential.VerifiableCredential
	Presentation *credential.VerifiablePresentation
	LDPFormat    *LinkedDataFormat

	// JWT claims
	Token     *string
	JWTFormat *JWTFormat

	// Always required

	// The algorithm or Linked Data proof type by which the claim was signed must be present
	SignatureAlgorithmOrProofType string
}

// GetClaim returns the claim value as a generic type. Since PresentationClaim is a union type, the value returned is
// the first non-nil value in the following order: Credential, Presentation, Token
func (pc *PresentationClaim) GetClaim() any {
	if pc.Credential != nil {
		return pc.Credential
	}
	if pc.Presentation != nil {
		return pc.Presentation
	}
	return pc.Token
}

func (pc *PresentationClaim) IsEmpty() bool {
	if pc == nil || (pc.Credential == nil && pc.Presentation == nil && pc.Token == nil) {
		return true
	}
	return reflect.DeepEqual(pc, &PresentationClaim{})
}

// GetClaimValue returns the value of the claim as JSON. Since PresentationClaim is a union type. An error
// is returned if no value is present in any of the possible embedded types.
func (pc *PresentationClaim) GetClaimValue() (any, error) {
	if pc.Credential != nil {
		return *pc.Credential, nil
	}
	if pc.Presentation != nil {
		return *pc.Presentation, nil
	}
	if pc.Token != nil {
		switch pc.JWTFormat.String() {
		case JWT.String(), JWTVC.String(), JWTVP.String():
			return jwt.Parse([]byte(*pc.Token), jwt.WithValidate(false), jwt.WithVerify(false))
		default:
			return nil, fmt.Errorf("unsupported JWT format: %s", pc.JWTFormat)
		}
	}
	return nil, errors.New("claim is empty")
}

// GetClaimFormat returns the value of the format depending on the claim type.
// Since PresentationClaim is a union type. An error is returned if
// no value is present in any of the possible embedded types.
func (pc *PresentationClaim) GetClaimFormat() (string, error) {
	if pc.Credential != nil {
		if pc.LDPFormat == nil {
			return "", errors.New("credential claim has no LDP format set")
		}
		return string(*pc.LDPFormat), nil
	}
	if pc.Presentation != nil {
		if pc.LDPFormat == nil {
			return "", errors.New("presentation claim has no LDP format set")
		}
		return string(*pc.LDPFormat), nil
	}
	if pc.Token != nil {
		if pc.JWTFormat == nil {
			return "", errors.New("JWT claim has no JWT format set")
		}
		return string(*pc.JWTFormat), nil
	}
	return "", errors.New("claim is empty")
}

// GetClaimJSON gets the claim value and attempts to turn it into a generic go-JSON object represented by an any
func (pc *PresentationClaim) GetClaimJSON() (map[string]any, error) {
	claimValue, err := pc.GetClaimValue()
	if err != nil {
		return nil, err
	}
	jsonClaim := make(map[string]any)

	// need to handle the case where we already have a string, since we won't need to marshal it
	var claimBytes []byte
	if claimStr, ok := claimValue.(string); ok {
		claimBytes = []byte(claimStr)
	} else {
		claimBytes, err = json.Marshal(claimValue)
		if err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(claimBytes, &jsonClaim); err != nil {
		return nil, err
	}
	return jsonClaim, nil
}

// BuildPresentationSubmission constructs a submission given a presentation definition, set of claims, and an
// embed target format.
// https://identity.foundation/presentation-exchange/#presentation-submission
// Note: this method does not support LD cryptosuites, and prefers JWT representations. Future refactors
// may include an analog method for LD suites.
func BuildPresentationSubmission(signer any, requester string, def PresentationDefinition, claims []PresentationClaim, et EmbedTarget) ([]byte, error) {
	if !IsSupportedEmbedTarget(et) {
		return nil, fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	normalizedClaims, err := normalizePresentationClaims(claims)
	if err != nil {
		return nil, errors.Wrap(err, "normalizing some presentation claims")
	}
	if len(normalizedClaims) == 0 {
		return nil, errors.New("no claims remain after normalization; cannot continue processing")
	}
	switch et {
	case JWTVPTarget:
		jwtSigner, ok := signer.(jwx.Signer)
		if !ok {
			return nil, fmt.Errorf("signer<%T> is not a JWXSigner", signer)
		}
		vpSubmission, err := BuildPresentationSubmissionVP(jwtSigner.ID, def, normalizedClaims)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fulfill presentation definition with given credentials")
		}
		return integrity.SignVerifiablePresentationJWT(jwtSigner, &integrity.JWTVVPParameters{Audience: []string{requester}}, *vpSubmission)
	default:
		return nil, fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

type NormalizedClaim struct {
	// id for the claim
	ID string
	// json representation of the claim
	Data map[string]any
	// claim in its original format (e.g. Verifiable Credential, token string, etc.)
	RawClaim any
	// JWT_VC, JWT_VP, LDP_VC, LDP_VP, etc.
	Format string
	// Signing algorithm used for the claim (e.g. EdDSA, ES256, PS256, etc.).
	// OR the Linked Data Proof Type (e.g. JsonWebSignature2020)
	AlgOrProofType string
}

// normalizePresentationClaims takes a set of Presentation Claims and turns them into map[string]any as
// go-JSON representations. The claim format and signature algorithm type are noted as well.
// This method is greedy, meaning it returns the set of claims it was able to normalize.
func normalizePresentationClaims(claims []PresentationClaim) ([]NormalizedClaim, error) {
	var normalizedClaims []NormalizedClaim
	errs := util.NewAppendError()
	for _, claim := range claims {
		ae := util.NewAppendError()
		claimJSON, err := claim.GetClaimJSON()
		if err != nil {
			ae.Append(err)
		}
		claimFormat, err := claim.GetClaimFormat()
		if err != nil {
			ae.Append(err)
		}
		if ae.Error() != nil {
			errs.Append(fmt.Errorf("could not normalize claim: %s", ae.Error().Error()))
			continue
		}
		var id string
		if claimID, ok := claimJSON["id"]; ok {
			id = claimID.(string)
		} else if claimID, ok := claimJSON["jti"]; ok {
			id = claimID.(string)
		}
		normalizedClaims = append(normalizedClaims, NormalizedClaim{
			ID:             id,
			Data:           claimJSON,
			RawClaim:       claim.GetClaim(),
			Format:         claimFormat,
			AlgOrProofType: claim.SignatureAlgorithmOrProofType,
		})
	}
	return normalizedClaims, errs.Error()
}

// processedClaim represents a claim that has been processed for an input descriptor along with relevant
// information for building a valid descriptor_map in the resulting presentation submission
type processedClaim struct {
	claim any
	SubmissionDescriptor
}

// BuildPresentationSubmissionVP takes a presentation definition and a set of claims. According to the presentation
// definition, and the algorithm defined - https://identity.foundation/presentation-exchange/#input-evaluation - in
// the specification, a presentation submission is constructed as a Verifiable Presentation.
func BuildPresentationSubmissionVP(submitter string, def PresentationDefinition, claims []NormalizedClaim) (*credential.VerifiablePresentation, error) {
	if err := canProcessDefinition(def); err != nil {
		return nil, errors.Wrap(err, "feature not supported in processing given presentation definition")
	}
	builder := credential.NewVerifiablePresentationBuilder()
	if err := builder.AddContext(PresentationSubmissionContext); err != nil {
		return nil, err
	}
	if err := builder.AddType(PresentationSubmissionType); err != nil {
		return nil, err
	}
	if err := builder.SetHolder(submitter); err != nil {
		return nil, err
	}

	submission := PresentationSubmission{
		ID:           uuid.NewString(),
		DefinitionID: def.ID,
	}

	// begin to process to presentation definition against the available claims
	var processedClaims []processedClaim
	claimIndex := 0
	// keep track of claims we've already added, to avoid duplicates
	seenClaims := make(map[string]int)
	for _, id := range def.InputDescriptors {
		processedDescriptor, err := processInputDescriptor(id, claims)
		if err != nil {
			return nil, errors.Wrapf(err, "error processing input descriptor: %s", id.ID)
		}
		if processedDescriptor == nil {
			return nil, fmt.Errorf("input descrpitor<%s> could not be fulfilled; could not build a valid presentation submission", id.ID)
		}

		// check if claim already exists. if it has, we won't duplicate the claim
		var currIndex int
		var claim any
		claimID := processedDescriptor.ClaimID
		if seen, ok := seenClaims[claimID]; ok {
			currIndex = seen
		} else {
			currIndex = claimIndex
			claimIndex++
			claim = processedDescriptor.Claim
			seenClaims[claimID] = currIndex
		}
		processedClaims = append(processedClaims, processedClaim{
			claim: claim,
			SubmissionDescriptor: SubmissionDescriptor{
				ID:     processedDescriptor.ID,
				Format: processedDescriptor.Format,
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", currIndex),
			},
		})
	}

	// set descriptor map in submission and credentials to the VP
	var descriptorMap []SubmissionDescriptor
	for _, claim := range processedClaims {
		descriptorMap = append(descriptorMap, claim.SubmissionDescriptor)
		// in the case where we've seen the claim, we need to check as to not add a nil claim value
		if claim.claim != nil {
			if err := builder.AddVerifiableCredentials(claim.claim); err != nil {
				return nil, errors.Wrap(err, "adding claim to verifiable presentation")
			}
		}
	}

	// add the built descriptor map to the submission
	submission.DescriptorMap = descriptorMap

	// set submission in vp, build, and return
	if err := builder.SetPresentationSubmission(submission); err != nil {
		return nil, err
	}
	return builder.Build()
}

// processedInputDescriptor
type processedInputDescriptor struct {
	// input descriptor id
	ID string
	// ID of the claim
	ClaimID string
	// generic claim
	Claim any
	// claim format
	Format string
}

// limitedInputDescriptor is the claim data after being filtered/limited via JSON path
type limitedInputDescriptor struct {
	Path string
	Data any
}

// processInputDescriptor runs the input evaluation algorithm described in the spec for a specific input descriptor
// https://identity.foundation/presentation-exchange/#input-evaluation
func processInputDescriptor(id InputDescriptor, claims []NormalizedClaim) (*processedInputDescriptor, error) {
	constraints := id.Constraints
	if constraints == nil {
		return nil, fmt.Errorf("unable to process input descriptor without constraints")
	}
	fields := constraints.Fields
	if len(fields) == 0 {
		return nil, fmt.Errorf("unable to process input descriptor without fields: %s", id.ID)
	}

	// bookkeeping to check whether we've fulfilled all required fields, and whether we need to limit disclosure
	fieldsToProcess := len(fields)
	disclosure := constraints.LimitDisclosure
	if disclosure != nil && *disclosure == Required {
		// TODO(gabe) enable limiting disclosure for ZKP/SD creds https://github.com/hesusruiz/eudiw-ssi-go/issues/354
		// otherwise, we won't be able to send back a claim with a signature attached
		return nil, errors.New("requiring limit disclosure is not supported")
	}

	// first, reduce the set of claims that conform with the format required by the input descriptor
	filteredClaims := filterClaimsByFormat(claims, id.Format)
	if len(filteredClaims) == 0 {
		return nil, fmt.Errorf("no claims match the required format, and jwt alg/proof type requirements "+
			"for input descriptor: %s", id.ID)
	}

	// for the input descriptor to be successfully processed each field needs to yield a result for a given claim,
	// so we need to iterate through each claim, and test it against each field, and each path within each field.
	// if we find a match for each field, we know a claim can fulfill the given input descriptor.
	for _, claim := range filteredClaims {
		fieldsProcessed := 0
		claimValue := claim.Data
		for _, field := range fields {
			// apply the field to the claim, and return the processed value, which we only care about for
			// filtering and/or limit_disclosure settings
			if _, fulfilled := processInputDescriptorField(field, claimValue); !fulfilled {
				// we know this claim is not sufficient to fulfill the input descriptor
				break
			}
			// we've fulfilled the field, so note it
			fieldsProcessed++
		}

		// if a claim has matched all fields, we can fulfill the input descriptor with this claim
		if fieldsProcessed == fieldsToProcess {
			return &processedInputDescriptor{
				ID:      id.ID,
				ClaimID: claim.ID,
				Claim:   claim.RawClaim,
				Format:  claim.Format,
			}, nil
		}
	}
	return nil, fmt.Errorf("no claims could fulfill the input descriptor: %s", id.ID)
}

// filterClaimsByFormat returns a set of claims that comply with a given ClaimFormat according to its
// supported format(s) and signature types per format
func filterClaimsByFormat(claims []NormalizedClaim, format *ClaimFormat) []NormalizedClaim {
	// no format, which is an optional property
	if format == nil {
		return claims
	}
	formatValues := format.FormatValues()
	var filteredClaims []NormalizedClaim
	for _, claim := range claims {
		// if the format matches, check the alg type
		if util.Contains(claim.Format, formatValues) {
			// get the supported alg or proof types for this format
			algOrProofTypes := format.AlgOrProofTypePerFormat()
			if util.Contains(claim.AlgOrProofType, algOrProofTypes) {
				filteredClaims = append(filteredClaims, claim)
			}
		}
	}
	return filteredClaims
}

// constructLimitedClaim builds a limited disclosure/filtered claim from a set of filtered input descriptors
func constructLimitedClaim(limitedDescriptors []limitedInputDescriptor) map[string]any {
	result := make(map[string]any)
	for _, ld := range limitedDescriptors {
		curr := result

		// normalize the current path to build JSON from
		normalizedPath := normalizeJSONPath(ld.Path)
		splitPath := strings.Split(normalizedPath, ".")
		for i := 0; i < len(splitPath)-1; i++ {
			// get and normalize the current section of the path
			part := splitPath[i]
			normalizedPart := normalizeJSONPartPath(part)

			// if it's empty, we continue to the next piece of the path
			if normalizedPart == "" {
				continue
			}

			// if the path is not contained in the resulting JSON, create it
			if _, ok := curr[normalizedPart]; !ok {
				curr[normalizedPart] = make(map[string]any)
			}

			// make sure the value is represented in curr
			currVal, _ := curr[normalizedPart]
			curr = currVal.(map[string]any)
		}

		// since we've gone to one short of the end, we need to repeat the process for the last element in the path
		// this is where we set the data value for the limited descriptor
		lastPartName := normalizeJSONPartPath(splitPath[len(splitPath)-1])
		curr[lastPartName] = ld.Data
	}

	return result
}

func normalizeJSONPartPath(partPath string) string {
	partRegex := regexp.MustCompile(`[^a-zA-Z]`)
	return partRegex.ReplaceAllString(partPath, "")
}

func normalizeJSONPath(path string) string {
	pathRegex := regexp.MustCompile(`\[.*]`)
	return pathRegex.ReplaceAllString(path, "")
}

// processInputDescriptorField applies all possible path values to a claim, and checks to see if any match.
// if a path matches fulfilled will be set to true and no processed value will be returned. if limitDisclosure is
// set to true, the processed value will be returned as well.
func processInputDescriptorField(field Field, claimData map[string]any) (*limitedInputDescriptor, bool) {
	for _, path := range field.Path {
		pathedData, err := jsonpath.JsonPathLookup(claimData, path)
		if err == nil {
			limited := &limitedInputDescriptor{
				Path: path,
				Data: pathedData,
			}
			return limited, true
		}
	}
	if field.Optional {
		return nil, true
	}
	return nil, false
}

// TODO(gabe) https://github.com/hesusruiz/eudiw-ssi-go/issues/56
// check for certain features we may not support yet: submission requirements, predicates, relational constraints,
// credential status, JSON-LD framing from https://identity.foundation/presentation-exchange/#features
func canProcessDefinition(def PresentationDefinition) error {
	if def.IsEmpty() {
		return errors.New("presentation definition cannot be empty")
	}
	submissionRequirementsErr := errors.New("submission requirements feature not supported")
	if len(def.SubmissionRequirements) > 0 {
		return submissionRequirementsErr
	}
	for _, id := range def.InputDescriptors {
		if id.Constraints != nil {
			if len(id.Group) > 0 {
				return submissionRequirementsErr
			}
			if len(id.Constraints.Fields) > 0 {
				for _, field := range id.Constraints.Fields {
					if field.Predicate != nil {
						return errors.New("predicate feature not supported")
					}
				}
			}
		}
	}
	for _, id := range def.InputDescriptors {
		if hasRelationalConstraint(id.Constraints) {
			return errors.New("relational constraint feature not supported")
		}
	}
	for _, id := range def.InputDescriptors {
		if id.Constraints != nil && id.Constraints.Statuses != nil {
			return errors.New("credential status constraint feature not supported")
		}
	}
	if def.Frame != nil {
		return errors.New("JSON-LD framing feature not supported")
	}
	return nil
}

// hasRelationalConstraint checks a constraint property for relational constraint field values
// except for subject is issuer, which is supported
func hasRelationalConstraint(constraints *Constraints) bool {
	if constraints == nil {
		return false
	}
	return constraints.IsHolder != nil || constraints.SameSubject != nil
}

func IsSupportedEmbedTarget(et EmbedTarget) bool {
	supported := GetSupportedEmbedTargets()
	for _, t := range supported {
		if et == t {
			return true
		}
	}
	return false
}

func GetSupportedEmbedTargets() []EmbedTarget {
	return []EmbedTarget{JWTVPTarget}
}
