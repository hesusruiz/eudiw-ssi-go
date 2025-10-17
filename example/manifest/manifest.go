// A simple example of making a credential manifest and issuing a credential from it, using a credential application.
// For simplicity the objects are not signed or verified cryptographically.
// |----------|     |--------------|      |--------|      |--------------|     |---------|      |-------_------|
// | Verifier  | --> |  Credential  | -->  | Holder | -->  |  Credential  | --> | Verifier | -->  |  Credential  |
// |          |     |   Manifest   |      |        |      |  Application |     |         |      |   Response   |
// |----------|     |--------------|      |--------|      |--------------|     |---------|      |--------------|
package main

import (
	gocrypto "crypto"
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/hesusruiz/eudiw-ssi-go/credential"
	"github.com/hesusruiz/eudiw-ssi-go/credential/exchange"
	"github.com/hesusruiz/eudiw-ssi-go/credential/manifest"
	"github.com/hesusruiz/eudiw-ssi-go/credential/rendering"
	"github.com/hesusruiz/eudiw-ssi-go/credential/schema"
	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/did/key"
	"github.com/hesusruiz/eudiw-ssi-go/example"
	"github.com/hesusruiz/eudiw-ssi-go/util"
)

// getDIDKey will return a DID key and its private key
func getDIDKey() (gocrypto.PrivateKey, *key.DIDKey, error) {
	return key.GenerateDIDKey(crypto.Ed25519)
}

// Prepare a credential schema that will be used to issue a credential from a successful Credential Manifest
func prepareCredentialSchema() schema.JSONSchema {
	return schema.JSONSchema{
		"id":          "ca-dmv-drivers-license-schema-1.0",
		"$schema":     "https://json-schema.org/draft/2019-09/schema",
		"description": "CA DMV Drivers License Schema",
		"type":        "object",
		"properties": map[string]any{
			"credentialSubject": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"firstName": map[string]any{
						"type": "string",
					},
					"lastName": map[string]any{
						"type": "string",
					},
					"dateOfBirth": map[string]any{
						"type": "string",
					},
					"licenseNumber": map[string]any{
						"type": "string",
					},
					"licenseClass": map[string]any{
						"type": "string",
					},
				},
			},
		},
		"required": []string{
			"firstName", "lastName", "dateOfBirth", "licenseNumber", "licenseClass",
		},
	}
}

// Credential Manifests are used to describe which credentials are available for issuance.
// For more information on credential manifests, please go to:
// https://identity.foundation/credential-manifest/#credential-manifest
func prepareCredentialManifest(issuerDID key.DIDKey, licenseSchemaID string) (*manifest.CredentialManifest, error) {
	// Create a new credential manifest builder
	builder := manifest.NewCredentialManifestBuilder()

	if err := builder.SetName("CA DMV Drivers License"); err != nil {
		return nil, err
	}

	if err := builder.SetDescription("CA DMV Drivers License Credential Manifest"); err != nil {
		return nil, err
	}

	// Set the given issuer's DID
	if err := builder.SetIssuer(manifest.Issuer{
		ID:   issuerDID.String(),
		Name: "CA DMV",
		Styles: &rendering.EntityStyleDescriptor{
			Background: &rendering.ColorResource{Color: "#FFFFFF"},
			Text:       &rendering.ColorResource{Color: "#000000"},
		},
	}); err != nil {
		return nil, err
	}

	// Set the output descriptor, which is the resulting credential
	if err := builder.SetOutputDescriptors([]manifest.OutputDescriptor{
		{
			ID:          uuid.NewString(),
			Schema:      licenseSchemaID,
			Name:        "Drivers License",
			Description: "A CA Drivers License",
			Styles: &rendering.EntityStyleDescriptor{
				Background: &rendering.ColorResource{Color: "#FFFFFF"},
				Text:       &rendering.ColorResource{Color: "#000000"},
			},
		},
	}); err != nil {
		return nil, err
	}

	// Set the input descriptors, which are the inputs required to issue the resulting credential
	if err := builder.SetPresentationDefinition(exchange.PresentationDefinition{
		ID: uuid.NewString(),
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID:      "firstName",
				Name:    "First Name",
				Purpose: "Provide your first name required to issue your drivers license",
				Format: &exchange.ClaimFormat{
					JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.Ed25519DSA}},
				},
				Constraints: &exchange.Constraints{
					SubjectIsIssuer: exchange.Preferred.Ptr(),
					Fields: []exchange.Field{
						{
							Path:     []string{"$.credentialSubject.firstName"},
							Optional: false,
						},
					},
				},
			},
			{
				ID:      "lastName",
				Name:    "Last Name",
				Purpose: "Provide your last name required to issue your drivers license",
				Format: &exchange.ClaimFormat{
					JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.Ed25519DSA}},
				},
				Constraints: &exchange.Constraints{
					SubjectIsIssuer: exchange.Preferred.Ptr(),
					Fields: []exchange.Field{
						{
							Path:     []string{"$.credentialSubject.lastName"},
							Optional: false,
						},
					},
				},
			},
			{
				ID:      "dateOfBirth",
				Name:    "Date of Birth",
				Purpose: "Provide your date of birth required to issue your drivers license",
				Format: &exchange.ClaimFormat{
					JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.Ed25519DSA}},
				},
				Constraints: &exchange.Constraints{
					SubjectIsIssuer: exchange.Preferred.Ptr(),
					Fields: []exchange.Field{
						{
							Path:     []string{"$.credentialSubject.dateOfBirth"},
							Optional: false,
						},
					},
				},
			},
		},
	}); err != nil {
		return nil, err
	}

	// Set the claim format which we'll accept as inputs
	if err := builder.SetClaimFormat(exchange.ClaimFormat{
		JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.Ed25519DSA}},
	}); err != nil {
		return nil, err
	}

	return builder.Build()
}

// Prepare a credential which is required to fill out the credential manifest's application's
// input descriptor's requirements
func issueApplicationCredential(id key.DIDKey, s schema.JSONSchema) (*credential.VerifiableCredential, error) {
	builder := credential.NewVerifiableCredentialBuilder(credential.GenerateIDValue)

	if err := builder.SetIssuer(id.String()); err != nil {
		return nil, err
	}

	if err := builder.SetCredentialSchema(credential.CredentialSchema{
		ID:   s.ID(),
		Type: schema.JSONSchemaType.String(),
	}); err != nil {
		return nil, err
	}

	if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
		return nil, err
	}

	if err := builder.SetExpirationDate(time.Now().AddDate(0, 0, 1).Format(time.RFC3339)); err != nil {
		return nil, err
	}

	if err := builder.SetCredentialSubject(map[string]any{
		"id":          id.String(),
		"firstName":   "Satoshi",
		"lastName":    "Nakamoto",
		"dateOfBirth": "1970-01-01",
	}); err != nil {
		return nil, err
	}

	return builder.Build()
}

// Prepare a credential application against a credential manifest
func prepareCredentialApplication(cm manifest.CredentialManifest, vc credential.VerifiableCredential) (*manifest.CredentialApplicationWrapper, error) {
	builder := manifest.NewCredentialApplicationBuilder(cm.ID)

	if err := builder.SetApplicationClaimFormat(exchange.ClaimFormat{
		JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.Ed25519DSA}},
	}); err != nil {
		return nil, err
	}

	if err := builder.SetApplicantID("did:example:123"); err != nil {
		return nil, err
	}

	format := string(exchange.JWTVC)
	if err := builder.SetPresentationSubmission(exchange.PresentationSubmission{
		ID:           uuid.NewString(),
		DefinitionID: cm.PresentationDefinition.ID,
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:     "firstName",
				Format: format,
				Path:   "$.verifiableCredentials[0]",
			},
			{
				ID:     "lastName",
				Format: format,
				Path:   "$.verifiableCredentials[0]",
			},
			{
				ID:     "dateOfBirth",
				Format: format,
				Path:   "$.verifiableCredentials[0]",
			},
		},
	}); err != nil {
		return nil, err
	}

	application, err := builder.Build()
	if err != nil {
		return nil, err
	}

	return &manifest.CredentialApplicationWrapper{
		CredentialApplication: *application,
		Credentials:           []any{vc},
	}, nil
}

// Prepare a credential which is required to fill out the credential manifest's application
type driversLicenseFields struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	DateOfBirth string `json:"dateOfBirth"`
}

func issueDriversLicenseCredential(issuerDID key.DIDKey, subjectDID string, s schema.JSONSchema, data driversLicenseFields) (*credential.VerifiableCredential, error) {
	builder := credential.NewVerifiableCredentialBuilder(credential.GenerateIDValue)

	if err := builder.SetIssuer(issuerDID.String()); err != nil {
		return nil, err
	}

	if err := builder.SetCredentialSchema(credential.CredentialSchema{
		ID:   s.ID(),
		Type: schema.JSONSchemaType.String(),
	}); err != nil {
		return nil, err
	}

	if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
		return nil, err
	}

	if err := builder.SetExpirationDate(time.Now().AddDate(0, 0, 1).Format(time.RFC3339)); err != nil {
		return nil, err
	}

	if err := builder.SetCredentialSubject(map[string]any{
		"id":            subjectDID,
		"firstName":     data.FirstName,
		"lastName":      data.LastName,
		"dateOfBirth":   data.DateOfBirth,
		"licenseNumber": "YXZ123",
		"licenseType":   "Class D",
	}); err != nil {
		return nil, err
	}

	return builder.Build()
}

// Prepare a credential given a valid credential application
func processCredentialApplication(cm manifest.CredentialManifest, ca manifest.CredentialApplicationWrapper, s schema.JSONSchema, issuerDID key.DIDKey) (*manifest.CredentialResponseWrapper, error) {
	credAppRequestBytes, err := json.Marshal(ca)
	if err != nil {
		return nil, err
	}

	request := make(map[string]any)
	if err = json.Unmarshal(credAppRequestBytes, &request); err != nil {
		return nil, err
	}

	// check if valid
	if _, err = manifest.IsValidCredentialApplicationForManifest(cm, request); err != nil {
		return nil, err
	}

	// if it is, we can issue a credential
	applicantCredential := ca.Credentials[0].(credential.VerifiableCredential)
	data := driversLicenseFields{
		FirstName:   applicantCredential.CredentialSubject["firstName"].(string),
		LastName:    applicantCredential.CredentialSubject["lastName"].(string),
		DateOfBirth: applicantCredential.CredentialSubject["dateOfBirth"].(string),
	}
	licenseCredential, err := issueDriversLicenseCredential(issuerDID, applicantCredential.CredentialSubject.GetID(), s, data)
	if err != nil {
		return nil, err
	}

	builder := manifest.NewCredentialResponseBuilder(cm.ID)
	if err = builder.SetApplicationID(ca.CredentialApplication.ID); err != nil {
		return nil, err
	}
	if err = builder.SetFulfillment([]exchange.SubmissionDescriptor{
		{
			ID:     ca.CredentialApplication.PresentationSubmission.DescriptorMap[0].ID,
			Format: string(exchange.JWTVC),
			Path:   "$.vc[0]",
		},
	}); err != nil {
		return nil, err
	}

	credentialResponse, err := builder.Build()
	if err != nil {
		return nil, err
	}

	return &manifest.CredentialResponseWrapper{
		CredentialResponse: *credentialResponse,
		Credentials:        []any{licenseCredential},
	}, nil
}

func main() {
	// Generate a DID key and its private key for the issuer of the credential - the DMV
	_, issuerDID, err := getDIDKey()
	example.HandleExampleError(err, "failed to create issuer DID")

	// Prepare a credential schema that will be issued to issue a credential from a successful Credential Manifest
	// this is the schema for the license credential
	credentialSchema := prepareCredentialSchema()

	// Prepare a credential manifest which requests information needed to issue a driver's license
	credentialManifest, err := prepareCredentialManifest(*issuerDID, credentialSchema.ID())
	example.HandleExampleError(err, "failed to create manifest")

	// Generate a DID key and its private key for the subject of the credential - the applicant
	_, applicantDID, err := getDIDKey()
	example.HandleExampleError(err, "failed to create applicant DID")

	// have the application self-issue a credential that will be used as input to the credential manifest
	applicationCredential, err := issueApplicationCredential(*applicantDID, credentialSchema)
	example.HandleExampleError(err, "failed to issue applicant a credential")

	// generate a credential application for the manifest
	credentialApplication, err := prepareCredentialApplication(*credentialManifest, *applicationCredential)
	example.HandleExampleError(err, "failed to create credential application")

	// submit the credential application to the issuer and verify it
	credentialResponse, err := processCredentialApplication(*credentialManifest, *credentialApplication, credentialSchema, *issuerDID)
	example.HandleExampleError(err, "failed to process credential application")

	jsonResponse, err := util.PrettyJSON(credentialResponse)
	example.HandleExampleError(err, "failed to jsonify response")

	fmt.Printf("Credential Response: %s", string(jsonResponse))
}
