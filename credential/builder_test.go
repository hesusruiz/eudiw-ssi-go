package credential

import (
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/util"

	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	// happy path build example from the spec
	// https://www.w3.org/TR/vc-data-model/#example-a-simple-example-of-a-verifiable-credential
	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]any{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"alumniOf": map[string]any{
			"id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			"name": []any{
				map[string]any{"value": "Example University",
					"lang": "en",
				}, map[string]any{
					"value": "Exemple d'Université",
					"lang":  "fr",
				},
			},
		},
	}

	knownCred := VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	err := knownCred.IsValid()
	assert.NoError(t, err)

	// re-build with our builder
	builder := NewVerifiableCredentialBuilder(EmptyIDValue)

	err = builder.AddContext(knownContext)
	assert.NoError(t, err)

	err = builder.SetID(knownID)
	assert.NoError(t, err)

	err = builder.AddType(knownType)
	assert.NoError(t, err)

	err = builder.SetIssuer(knownIssuer)
	assert.NoError(t, err)

	err = builder.SetIssuanceDate(knownIssuanceDate)
	assert.NoError(t, err)

	err = builder.SetCredentialSubject(knownSubject)
	assert.NoError(t, err)

	credential, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, credential)

	assert.EqualValues(t, knownCred, *credential)
}

// TestCredentialBuilder Exercises all builder methods
func TestCredentialBuilder(t *testing.T) {
	builder := NewVerifiableCredentialBuilder(EmptyIDValue)
	assert.Empty(t, builder.ID)

	builder = NewVerifiableCredentialBuilder(IDValue("customid-123"))
	assert.Equal(t, builder.ID, "customid-123")

	builder = NewVerifiableCredentialBuilder(GenerateIDValue)
	_, err := builder.Build()
	assert.Error(t, err)
	notReadyErr := "credential not ready to be built"
	assert.Contains(t, err.Error(), notReadyErr)

	assert.False(t, builder.IsEmpty())

	// default context should be set
	assert.NotEmpty(t, builder.Context)

	// set context of a bad type
	err = builder.AddContext(4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed context")

	// correct context
	err = builder.AddContext("https://www.w3.org/2018/credentials/examples/v1")
	assert.NoError(t, err)

	// default id is not empty
	assert.NotEmpty(t, builder.ID)

	// set id
	id := "p"
	err = builder.SetID(id)
	assert.NoError(t, err)

	// set bad type value
	err = builder.AddType(5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed type")

	// valid type as a string
	err = builder.AddType("TestType")
	assert.NoError(t, err)

	// valid type as a []string
	err = builder.AddType([]string{"TestType"})
	assert.NoError(t, err)

	// set issuer as a string
	err = builder.SetIssuer("issuer")
	assert.NoError(t, err)

	// reset issuer as an object without an id property
	badIssuerObject := map[string]any{
		"issuer": "abcd",
		"bad":    "efghi",
	}
	err = builder.SetIssuer(badIssuerObject)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer object did not contain `id` property")

	// issuer object with an id property
	goodIssuerObject := map[string]any{
		"id": "issuer",
	}
	err = builder.SetIssuer(goodIssuerObject)
	assert.NoError(t, err)

	// bad date
	err = builder.SetIssuanceDate("not-a-date")
	assert.Error(t, err)

	// good date
	issuedAt := util.GetRFC3339Timestamp()
	err = builder.SetIssuanceDate(issuedAt)
	assert.NoError(t, err)

	// bad date
	err = builder.SetExpirationDate("not-a-date")
	assert.Error(t, err)

	// good date
	expiresAt := util.GetRFC3339Timestamp()
	err = builder.SetExpirationDate(expiresAt)
	assert.NoError(t, err)

	// incomplete credential status
	badStatus := DefaultCredentialStatus{
		Type: "StatusObject",
	}
	err = builder.SetCredentialStatus(badStatus)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status must contain an `id` property")

	// good status
	status := DefaultCredentialStatus{
		ID:   "status-id",
		Type: "status-type",
	}
	err = builder.SetCredentialStatus(status)
	assert.NoError(t, err)

	// cred subject - no id
	subjectWithMissingID := CredentialSubject{
		"name": "Satoshi",
	}
	err = builder.SetCredentialSubject(subjectWithMissingID)
	assert.NoError(t, err)

	// good subject
	subject := CredentialSubject{
		"id":   "subject-id",
		"name": "Satoshi",
	}
	err = builder.SetCredentialSubject(subject)
	assert.NoError(t, err)

	// bad cred schema - missing field
	badSchema := CredentialSchema{
		ID: "schema-id",
	}
	err = builder.SetCredentialSchema(badSchema)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential schema not valid")

	// good cred schema
	schema := CredentialSchema{
		ID:   "schema-id",
		Type: "schema-type",
	}
	err = builder.SetCredentialSchema(schema)
	assert.NoError(t, err)

	// bad refresh service - missing field
	badRefreshService := RefreshService{
		ID: "refresh-id",
	}
	err = builder.SetRefreshService(badRefreshService)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "refresh service not valid")

	// good refresh service
	refreshService := RefreshService{
		ID:   "refresh-id",
		Type: "refresh-type",
	}
	err = builder.SetRefreshService(refreshService)
	assert.NoError(t, err)

	// empty terms
	err = builder.SetTermsOfUse([]TermsOfUse{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "terms of use cannot be empty")

	// valid terms
	terms := []TermsOfUse{{Type: "terms", ID: "terms-id"}}
	err = builder.SetTermsOfUse(terms)
	assert.NoError(t, err)

	// empty evidence
	err = builder.SetEvidence([]any{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "evidence cannot be empty")

	// valid evidence
	evidence := []any{"evidence"}
	err = builder.SetEvidence(evidence)
	assert.NoError(t, err)

	// build it and verify some values
	cred, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, cred)

	assert.Equal(t, id, cred.ID)
	assert.Equal(t, issuedAt, cred.IssuanceDate)
	assert.Equal(t, expiresAt, cred.ExpirationDate)
	assert.Equal(t, goodIssuerObject, cred.Issuer)
	assert.Equal(t, schema, *cred.CredentialSchema)
	assert.Equal(t, subject, cred.CredentialSubject)
	assert.Equal(t, evidence, cred.Evidence)
	assert.Equal(t, terms, cred.TermsOfUse)
}

func TestVerifiablePresentationBuilder(t *testing.T) {
	badBuilder := VerifiablePresentationBuilder{}
	_, err := badBuilder.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "builder cannot be empty")

	badBuilder = VerifiablePresentationBuilder{
		VerifiablePresentation: &VerifiablePresentation{
			ID: "test-id",
		},
	}
	_, err = badBuilder.Build()
	assert.Contains(t, err.Error(), "presentation not ready to be built")

	builder := NewVerifiablePresentationBuilder()
	_, err = builder.Build()
	assert.NoError(t, err)

	// default context should be set
	assert.NotEmpty(t, builder.Context)

	// set context of a bad type
	err = builder.AddContext(4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed context")

	// correct context
	err = builder.AddContext("https://www.w3.org/2018/credentials/examples/v1")
	assert.NoError(t, err)

	// there is a default id
	assert.NotEmpty(t, builder.ID)

	// set id
	id := "test-id"
	err = builder.SetID(id)
	assert.NoError(t, err)

	// set bad type value
	err = builder.AddType(5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed type")

	// valid type as a string
	err = builder.AddType("TestType")
	assert.NoError(t, err)

	// valid type as a []string
	err = builder.AddType([]string{"TestType"})
	assert.NoError(t, err)

	// add two credentials
	creds := []any{
		VerifiableCredential{
			ID:     "cred-1",
			Type:   "type",
			Issuer: "issuer-1",
		},
		VerifiableCredential{
			ID:     "cred-2",
			Type:   "type",
			Issuer: "issuer-2",
		},
	}
	err = builder.AddVerifiableCredentials(creds...)
	assert.NoError(t, err)

	// build it and verify some values
	pres, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, pres)

	assert.Equal(t, id, pres.ID)
	assert.True(t, 2 == len(pres.VerifiableCredential))
}
