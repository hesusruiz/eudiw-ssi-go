package exchange

import (
	"context"
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/credential/integrity"
	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite/jws2020"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/did/key"
	"github.com/hesusruiz/eudiw-ssi-go/did/resolution"
	"github.com/hesusruiz/eudiw-ssi-go/util"

	"github.com/hesusruiz/eudiw-ssi-go/credential"
	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/cryptosuite"
)

func TestBuildPresentationSubmission(t *testing.T) {
	t.Run("Unsupported embed target", func(tt *testing.T) {
		_, err := BuildPresentationSubmission(jwx.Signer{}, "requester", PresentationDefinition{}, nil, "badEmbedTarget")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported presentation submission embed target type")
	})

	t.Run("Supported embed target, unsigned credential", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.iss", "$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
								Filter: &Filter{
									Type:      "string",
									MinLength: 1,
								},
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		signer, verifier := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential(signer.ID, signer.ID)
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		submissionBytes, err := BuildPresentationSubmission(*signer, signer.ID, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, _, _, err = integrity.VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, string(submissionBytes))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("Supported embed target with JWT credential", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.iss", "$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		signer, verifier := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential(signer.ID, signer.ID)

		credJWT, err := integrity.SignVerifiableCredentialJWT(*signer, testVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credJWT)

		presentationClaim := PresentationClaim{
			Token:                         util.StringPtr(string(credJWT)),
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: signer.ALG,
		}
		submissionBytes, err := BuildPresentationSubmission(*signer, signer.ID, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, _, vp, err := integrity.VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, string(submissionBytes))
		assert.NoError(tt, err)

		assert.NoError(tt, vp.IsValid())
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
	})
}

func TestBuildPresentationSubmissionVP(t *testing.T) {
	t.Run("Single input descriptor definition with single claim", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.iss", "$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
								Filter: &Filter{
									Type:      "string",
									MinLength: 1,
								},
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		vp, err := BuildPresentationSubmissionVP("submitter", def, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vp)

		// validate the submission is properly constructed
		assert.NotEmpty(tt, vp.PresentationSubmission)
		asSubmission, ok := vp.PresentationSubmission.(PresentationSubmission)
		assert.True(tt, ok)
		assert.NoError(tt, asSubmission.IsValid())
		assert.Equal(tt, def.ID, asSubmission.DefinitionID)
		assert.Equal(tt, 1, len(asSubmission.DescriptorMap))
		assert.Equal(tt, def.InputDescriptors[0].ID, asSubmission.DescriptorMap[0].ID)
		assert.EqualValues(tt, LDPVC, asSubmission.DescriptorMap[0].Format)

		// validate the vc result exists in the VP
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
		vcBytes, err := json.Marshal(vp.VerifiableCredential[0])
		assert.NoError(tt, err)
		var asVC credential.VerifiableCredential
		err = json.Unmarshal(vcBytes, &asVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVC)

		assert.Equal(tt, "test-verifiable-credential", asVC.ID)
		assert.Equal(tt, "Block", asVC.CredentialSubject["company"])
	})

	t.Run("Single input descriptor definition with no matching claims", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:     []string{"$.iss", "$.vc.issuer", "$.issuer"},
								ID:       "issuer-input-descriptor",
								Purpose:  "need to check the issuer",
								Optional: false,
								Filter: &Filter{
									Type:      "string",
									MinLength: 1,
								},
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		vp, err := BuildPresentationSubmissionVP("submitter", def, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no claims match the required format, and jwt alg/proof type requirements for input descriptor")
		assert.Empty(tt, vp)
	})

	t.Run("Two input descriptors with single claim that matches both", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.iss", "$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
								Filter: &Filter{
									Type:      "string",
									MinLength: 1,
								},
							},
						},
					},
				},
				{
					ID: "id-2",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.jti", "$.vc.id", "$.id"},
								ID:      "id-input-descriptor",
								Purpose: "need to check the id",
								Filter: &Filter{
									Type:      "string",
									MinLength: 1,
								},
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		vp, err := BuildPresentationSubmissionVP("submitter", def, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vp)

		// validate the submission is properly constructed
		assert.NotEmpty(tt, vp.PresentationSubmission)
		asSubmission, ok := vp.PresentationSubmission.(PresentationSubmission)
		assert.True(tt, ok)
		assert.NoError(tt, asSubmission.IsValid())
		assert.Equal(tt, def.ID, asSubmission.DefinitionID)
		assert.Equal(tt, 2, len(asSubmission.DescriptorMap))
		assert.Equal(tt, def.InputDescriptors[0].ID, asSubmission.DescriptorMap[0].ID)
		assert.EqualValues(tt, LDPVC, asSubmission.DescriptorMap[0].Format)

		// validate the vc result exists in the VP
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
		vcBytes, err := json.Marshal(vp.VerifiableCredential[0])
		assert.NoError(tt, err)
		var asVC credential.VerifiableCredential
		err = json.Unmarshal(vcBytes, &asVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVC)

		assert.Equal(tt, "test-verifiable-credential", asVC.ID)
		assert.Equal(tt, "Block", asVC.CredentialSubject["company"])
	})

	t.Run("Two input descriptors with two claims that match one input descriptor", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
				{
					ID: "id-2",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.credentialSubject.name"},
								ID:      "name-input-descriptor",
								Purpose: "need to check the name contains Jim",
								Filter: &Filter{
									Type:    "string",
									Pattern: "Jim*",
								},
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		testVCJWT := getTestJWTVerifiableCredential()
		presentationClaimJWT := PresentationClaim{
			Token:                         util.StringPtr(string(testVCJWT)),
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.Ed25519DSA),
		}

		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim, presentationClaimJWT})
		assert.NoError(tt, err)
		vp, err := BuildPresentationSubmissionVP("submitter", def, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vp)

		// validate the submission is properly constructed
		assert.NotEmpty(tt, vp.PresentationSubmission)
		asSubmission, ok := vp.PresentationSubmission.(PresentationSubmission)
		assert.True(tt, ok)
		assert.NoError(tt, asSubmission.IsValid())
		assert.Equal(tt, def.ID, asSubmission.DefinitionID)
		assert.Equal(tt, 2, len(asSubmission.DescriptorMap))
		assert.Equal(tt, def.InputDescriptors[0].ID, asSubmission.DescriptorMap[0].ID)
		assert.EqualValues(tt, LDPVC, asSubmission.DescriptorMap[0].Format)

		// validate the vc result exists in the VP
		assert.Equal(tt, 2, len(vp.VerifiableCredential))
		vcBytes, err := json.Marshal(vp.VerifiableCredential[0])
		assert.NoError(tt, err)
		var asVC credential.VerifiableCredential
		err = json.Unmarshal(vcBytes, &asVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVC)

		assert.Equal(tt, "test-verifiable-credential", asVC.ID)
		assert.Equal(tt, "Block", asVC.CredentialSubject["company"])

		_, vcJWTToken, asVCJWT, err := integrity.ParseVerifiableCredentialFromJWT(*(vp.VerifiableCredential[1].(*string)))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vcJWTToken)
		assert.NotEmpty(tt, asVCJWT)

		assert.Equal(tt, "did:example:456", vcJWTToken.Subject())
		assert.Equal(tt, "JimBobertson", asVCJWT.CredentialSubject["name"])
	})
}

func TestProcessInputDescriptor(t *testing.T) {
	t.Run("Simple Descriptor with One VC Claim", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path:     []string{"$.vc.issuer", "$.issuer"},
						ID:       "issuer-input-descriptor",
						Purpose:  "need to check the issuer",
						Optional: true,
					},
				},
			},
		}
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		processed, err := processInputDescriptor(id, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, processed)
		assert.Equal(tt, id.ID, processed.ID)

		// make sure it's not limited disclosure
		vc := processed.Claim.(*credential.VerifiableCredential)
		assert.Equal(tt, "test-verifiable-credential", vc.ID)
	})

	// TODO(gabe): update with https://github.com/hesusruiz/eudiw-ssi-go/issues/354
	t.Run("Simple Descriptor with One VC Claim and Limited Disclosure", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				LimitDisclosure: Required.Ptr(),
				Fields: []Field{
					{
						Path:    []string{"$.vc.issuer", "$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
		}
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		_, err = processInputDescriptor(id, normalized)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "requiring limit disclosure is not supported")
	})

	t.Run("Descriptor with no matching paths", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				LimitDisclosure: Preferred.Ptr(),
				Fields: []Field{
					{
						Path:    []string{"$.vc.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
		}
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		_, err = processInputDescriptor(id, normalized)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no claims could fulfill the input descriptor: id-1")
	})

	t.Run("Descriptor with no matching format", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path:    []string{"$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
			Format: &ClaimFormat{
				LDP: &LDPType{
					ProofType: []cryptosuite.SignatureType{jws2020.JSONWebSignature2020},
				},
			},
		}
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		_, err = processInputDescriptor(id, normalized)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no claims match the required format, and jwt alg/proof type requirements")
	})

	t.Run("Descriptor with matching format", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path:    []string{"$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
			Format: &ClaimFormat{
				LDPVC: &LDPType{
					ProofType: []cryptosuite.SignatureType{jws2020.JSONWebSignature2020},
				},
			},
		}
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		processed, err := processInputDescriptor(id, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, processed)
		assert.Equal(tt, id.ID, processed.ID)
	})
}

func TestCanProcessDefinition(tt *testing.T) {
	tt.Run("With Submission Requirements", func(t *testing.T) {
		def := PresentationDefinition{
			ID: "submission-requirements",
			SubmissionRequirements: []SubmissionRequirement{{
				Rule: All,
				FromOption: FromOption{
					From: "A",
				},
			}},
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "submission requirements feature not supported")
	})

	tt.Run("With Predicates", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "with-predicate",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-predicate",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Predicate: Allowed.Ptr(),
							},
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "predicate feature not supported")
	})

	tt.Run("With Relational Constraint", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "with-relational-constraint",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-relational-constraint",
					Constraints: &Constraints{
						IsHolder: []RelationalConstraint{
							{
								FieldID:   []string{"field-id"},
								Directive: Allowed.Ptr(),
							},
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "relational constraint feature not supported")
	})

	tt.Run("With Credential Status", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "with-credential-status",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-credential-status",
					Constraints: &Constraints{
						Statuses: &CredentialStatus{
							Active: &struct {
								Directive Preference `json:"directive,omitempty"`
							}{
								Directive: Required,
							},
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential status constraint feature not supported")
	})

	tt.Run("With LD Framing", func(t *testing.T) {
		def := PresentationDefinition{
			ID:    "with-ld-framing",
			Frame: "@context",
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JSON-LD framing feature not supported")
	})
}

func TestConstructLimitedClaim(t *testing.T) {
	t.Run("Full Claim With Nesting", func(tt *testing.T) {
		claim := getGenericTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		typePath := "$.type"
		typeValue, err := jsonpath.JsonPathLookup(claim, typePath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: typePath,
			Data: typeValue,
		})

		issuerPath := "$.issuer"
		issuerValue, err := jsonpath.JsonPathLookup(claim, issuerPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: issuerPath,
			Data: issuerValue,
		})

		idPath := "$.credentialSubject.id"
		idValue, err := jsonpath.JsonPathLookup(claim, idPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: idPath,
			Data: idValue,
		})

		namePath := "$.credentialSubject.firstName"
		nameValue, err := jsonpath.JsonPathLookup(claim, namePath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: namePath,
			Data: nameValue,
		})

		favoritesPath := "$.credentialSubject.favorites.citiesByState.CA"
		favoritesValue, err := jsonpath.JsonPathLookup(claim, favoritesPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: favoritesPath,
			Data: favoritesValue,
		})

		result := constructLimitedClaim(limitedDescriptors)
		assert.NotEmpty(tt, result)

		issuerRes, ok := result["issuer"]
		assert.True(tt, ok)
		assert.Equal(tt, issuerRes, "did:example:123")

		credSubjRes, ok := result["credentialSubject"]
		assert.True(tt, ok)

		id, ok := credSubjRes.(map[string]any)["id"]
		assert.True(tt, ok)
		assert.Contains(tt, id, "test-id")

		favoritesRes, ok := credSubjRes.(map[string]any)["favorites"]
		assert.True(tt, ok)
		assert.NotEmpty(tt, favoritesRes)

		statesRes, ok := favoritesRes.(map[string]any)["citiesByState"]
		assert.True(tt, ok)
		assert.Contains(tt, statesRes, "CA")

		citiesRes, ok := statesRes.(map[string]any)["CA"]
		assert.True(tt, ok)
		assert.Contains(tt, citiesRes, "Oakland")
	})

	t.Run("Complex Path Parsing", func(tt *testing.T) {
		claim := getGenericTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		filterPath := "$.credentialSubject.address[?(@.number > 0)]"
		filterValue, err := jsonpath.JsonPathLookup(claim, filterPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: filterPath,
			Data: filterValue,
		})

		result := constructLimitedClaim(limitedDescriptors)
		assert.NotEmpty(tt, result)

		// make sure the result contains a value
		csValue, ok := result["credentialSubject"]
		assert.True(tt, ok)
		assert.NotEmpty(tt, csValue)

		addressValue, ok := csValue.(map[string]any)["address"]
		assert.True(tt, ok)
		assert.Contains(tt, addressValue, "road street")
		assert.Contains(tt, addressValue, "USA")
	})
}

func getTestVerifiableCredential(issuerDID, subjectDID string) credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context: []any{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		ID:           "test-verifiable-credential",
		Type:         []string{"VerifiableCredential"},
		Issuer:       issuerDID,
		IssuanceDate: "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id":      subjectDID,
			"company": "Block",
			"website": "https://block.xyz",
		},
	}
}

func getTestVerifiablePresentation() credential.VerifiablePresentation {
	return credential.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		ID:      "test-verifiable-presentation",
		Type:    []string{"VerifiablePresentation"},
		VerifiableCredential: []any{
			credential.VerifiableCredential{
				Context: []any{"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/security/suites/jws-2020/v1"},
				ID:           "test-vp-verifiable-credential",
				Type:         []string{"VerifiableCredential"},
				Issuer:       "test-issuer",
				IssuanceDate: "2021-01-01T19:23:24Z",
				CredentialSubject: map[string]any{
					"id":      "test-vp-vc-id",
					"company": "TBD",
					"github":  "https://github.com/TBD54566975",
				},
			},
		},
	}
}

func TestNormalizePresentationClaims(t *testing.T) {
	t.Run("Normalize JWT Claim", func(tt *testing.T) {
		jwtVC := getTestJWTVerifiableCredential()
		assert.NotEmpty(tt, jwtVC)

		presentationClaim := PresentationClaim{
			Token:                         util.StringPtr(string(jwtVC)),
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.Ed25519DSA),
		}

		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].Data)
		assert.EqualValues(tt, JWTVC, normalized[0].Format)
		assert.EqualValues(tt, string(crypto.Ed25519DSA), normalized[0].AlgOrProofType)
	})

	t.Run("Normalize VP Claim", func(tt *testing.T) {
		vpClaim := getTestVerifiablePresentation()
		assert.NotEmpty(tt, vpClaim)

		presentationClaim := PresentationClaim{
			Presentation:                  &vpClaim,
			LDPFormat:                     LDPVP.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}

		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].Data)
		assert.EqualValues(tt, LDPVP, normalized[0].Format)
		assert.EqualValues(tt, string(jws2020.JSONWebSignature2020), normalized[0].AlgOrProofType)
	})

	t.Run("Normalize VC Claim", func(tt *testing.T) {
		vcClaim := getTestVerifiableCredential("test-issuer", "test-subject")
		assert.NotEmpty(tt, vcClaim)

		presentationClaim := PresentationClaim{
			Credential:                    &vcClaim,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}

		normalized, err := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].Data)
		assert.EqualValues(tt, LDPVC, normalized[0].Format)
		assert.EqualValues(tt, string(jws2020.JSONWebSignature2020), normalized[0].AlgOrProofType)
	})
}

func getTestJWTVerifiableCredential() []byte {
	// {
	//  "alg": "EdDSA",
	//  "typ": "JWT"
	// }
	// {
	//  "iat": 1609529004,
	//  "iss": "did:example:123",
	//  "jti": "http://example.edu/credentials/1872",
	//  "nbf": 1609529004,
	//  "nonce": "24976372-adc4-4808-90c2-d86ea805e11b",
	//  "sub": "did:example:456",
	//  "vc": {
	//    "@context": [
	//      "https://www.w3.org/2018/credentials/v1",
	//      "https://w3id.org/security/suites/jws-2020/v1"
	//    ],
	//    "type": [
	//      "VerifiableCredential"
	//    ],
	//    "issuer": "",
	//    "issuanceDate": "",
	//    "credentialSubject": {
	//      "name": "JimBobertson"
	//    }
	//  }
	// }
	return []byte("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MDk1MjkwMDQsImlzcyI6ImRpZDpleGFtcGxlOjEyMyIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZW50aWFscy8xODcyIiwibmJmIjoxNjA5NTI5MDA0LCJub25jZSI6IjI0OTc2MzcyLWFkYzQtNDgwOC05MGMyLWQ4NmVhODA1ZTExYiIsInN1YiI6ImRpZDpleGFtcGxlOjQ1NiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eS9zdWl0ZXMvandzLTIwMjAvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiIiLCJpc3N1YW5jZURhdGUiOiIiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoiSmltQm9iZXJ0c29uIn19fQ.STf2oFVPTwEyEhCpU_u9Qy52VzAwHlWtxq2NrlXhzvh0aJIbr5astEagEY2PRZ_S6Og-7Q4sYTT7sq6HJSjLBA")
}

func getGenericTestClaim() map[string]any {
	return map[string]any{
		"@context": []any{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		"type":         []string{"VerifiableCredential"},
		"issuer":       "did:example:123",
		"issuanceDate": "2021-01-01T19:23:24Z",
		"credentialSubject": map[string]any{
			"id":        "test-id",
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
			"address": map[string]any{
				"number":  1,
				"street":  "road street",
				"country": "USA",
			},
			"favorites": map[string]any{
				"color": "blue",
				"citiesByState": map[string]any{
					"NY": []string{"NY"},
					"CA": []string{"Oakland", "San Francisco"},
				},
			},
		},
	}
}

func getJWKSignerVerifier(t *testing.T) (*jwx.Signer, *jwx.Verifier) {
	privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
	require.NoError(t, err)

	expanded, err := didKey.Expand()
	require.NoError(t, err)
	kid := expanded.VerificationMethod[0].ID
	signer, err := jwx.NewJWXSigner(didKey.String(), &kid, privKey)
	require.NoError(t, err)

	verifier, err := signer.ToVerifier(didKey.String())
	require.NoError(t, err)

	return signer, verifier
}
