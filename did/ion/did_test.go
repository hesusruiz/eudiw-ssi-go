package ion

import (
	"context"
	"net/http"
	"testing"

	"github.com/hesusruiz/eudiw-ssi-go/crypto/jwx"
	"github.com/hesusruiz/eudiw-ssi-go/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

// Test vector from https://identity.foundation/sidetree/spec/#long-form-response, adjusted by replacing s/sidetree/ion/
// and adding a `didResolutionMetadata` property (this is required by https://www.w3.org/TR/did-core/#did-resolution).
func TestResolveLongFormDID(t *testing.T) {
	longFormDID := `did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ`
	resolver, err := NewIONResolver(http.DefaultClient, "https://example.com")
	assert.NoError(t, err)

	resolutionResult, err := resolver.Resolve(context.Background(), longFormDID)
	assert.NoError(t, err)

	jsonResolutionResult, err := json.Marshal(resolutionResult)
	assert.NoError(t, err)

	expectedResolutionResultJSON := `{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "id": "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ",
    "@context": [
      "https://www.w3.org/ns/did/v1",
      {
        "@base": "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"
      }
    ],
    "service": [
      {
        "id": "#service1Id",
        "type": "service1Type",
        "serviceEndpoint": "http://www.service1.com"
      }
    ],
    "verificationMethod": [
      {
        "id": "#publicKeyModel1Id",
        "controller": "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "publicKeyJwk": {
          "crv": "secp256k1",
          "kty": "EC",
          "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
          "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
        }
      }
    ],
    "authentication": [
      "#publicKeyModel1Id"
    ],
    "keyAgreement": [
      "#publicKeyModel1Id"
    ]
  },
  "didDocumentMetadata": {
    "equivalentId": ["did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"],
    "method": {
      "published": false,
      "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA",
      "updateCommitment": "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA"
    }
  },
  "didResolutionMetadata": {
  }
}`
	assert.JSONEq(t, expectedResolutionResultJSON, string(jsonResolutionResult))
}

// https://github.com/decentralized-identity/ion-sdk/blob/main/tests/IonDid.spec.ts#L18
func TestCreateLongFormDID(t *testing.T) {
	var recoveryKey jwx.PublicKeyJWK
	retrieveTestVectorAs(t, "jwkes256k1public.json", &recoveryKey)

	var updateKey jwx.PublicKeyJWK
	retrieveTestVectorAs(t, "jwkes256k2public.json", &updateKey)

	var publicKey PublicKey
	retrieveTestVectorAs(t, "publickeymodel1.json", &publicKey)

	var service did.Service
	retrieveTestVectorAs(t, "service1.json", &service)

	document := Document{
		PublicKeys: []PublicKey{
			publicKey,
		},
		Services: []did.Service{
			service,
		},
	}

	longFormDID, err := CreateLongFormDID(recoveryKey, updateKey, document)
	assert.NoError(t, err)
	assert.NotEmpty(t, longFormDID)

	expectedLongFormDID := "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"
	assert.Equal(t, expectedLongFormDID, longFormDID)

	expectedDID, expectedIS, err := DecodeLongFormDID(expectedLongFormDID)
	assert.NoError(t, err)

	ourDID, ourInitialState, ourErr := DecodeLongFormDID(longFormDID)
	assert.NoError(t, ourErr)

	assert.Equal(t, expectedDID, ourDID)
	assert.Equal(t, expectedIS, ourInitialState)

	shortFormDID, longFormDID, err := ourInitialState.ToDIDStrings()
	assert.NoError(t, err)
	assert.NotEmpty(t, longFormDID)
	assert.NotEmpty(t, shortFormDID)
	assert.Equal(t, expectedLongFormDID, longFormDID)
	assert.Equal(t, "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", shortFormDID)
}

func TestCreateShortFormDID(t *testing.T) {
	knownSuffixData := SuffixData{
		DeltaHash:          "EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg",
		RecoveryCommitment: "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA",
	}

	shortFormDID, err := CreateShortFormDID(knownSuffixData)
	assert.NoError(t, err)
	assert.NotEmpty(t, shortFormDID)

	assert.Equal(t, shortFormDID, "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg")
}

func TestGetShortFormDIDFromLongFormDID(t *testing.T) {
	var recoveryKey jwx.PublicKeyJWK
	retrieveTestVectorAs(t, "jwkes256k1public.json", &recoveryKey)

	var updateKey jwx.PublicKeyJWK
	retrieveTestVectorAs(t, "jwkes256k2public.json", &updateKey)

	var publicKey PublicKey
	retrieveTestVectorAs(t, "publickeymodel1.json", &publicKey)

	var service did.Service
	retrieveTestVectorAs(t, "service1.json", &service)

	document := Document{
		PublicKeys: []PublicKey{
			publicKey,
		},
		Services: []did.Service{
			service,
		},
	}

	longFormDID, err := CreateLongFormDID(recoveryKey, updateKey, document)
	assert.NoError(t, err)
	assert.NotEmpty(t, longFormDID)

	shortFormDID, err := LongToShortFormDID(longFormDID)
	assert.NoError(t, err)
	assert.NotEmpty(t, shortFormDID)

	assert.Equal(t, shortFormDID, "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg")
}

func TestPatchesToDIDDocument(t *testing.T) {
	t.Run("Bad patch", func(tt *testing.T) {
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{AddPublicKeysAction{}})
		assert.Empty(tt, doc)
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "unknown patch type")
	})

	t.Run("No patches", func(tt *testing.T) {
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{})
		assert.Empty(tt, doc)
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "no patches to apply")
	})

	t.Run("Single patch - add keys", func(tt *testing.T) {
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{
			AddPublicKeysAction{
				Action: AddPublicKeys,
				PublicKeys: []PublicKey{{
					ID:       "did:ion:test#key1",
					Purposes: []did.PublicKeyPurpose{did.Authentication, did.AssertionMethod},
				}},
			}})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, doc)
		assert.Len(tt, doc.VerificationMethod, 1)
		assert.Len(tt, doc.Authentication, 1)
		assert.Equal(tt, "did:ion:test#key1", doc.Authentication[0])
		assert.Len(tt, doc.AssertionMethod, 1)
		assert.Equal(tt, "did:ion:test#key1", doc.AssertionMethod[0])

		assert.Empty(tt, doc.KeyAgreement)
		assert.Empty(tt, doc.CapabilityDelegation)
		assert.Empty(tt, doc.CapabilityInvocation)
	})

	t.Run("Add and remove keys patches - invalid remove", func(tt *testing.T) {
		addKeys := AddPublicKeysAction{
			Action: AddPublicKeys,
			PublicKeys: []PublicKey{{
				ID:       "did:ion:test#key1",
				Purposes: []did.PublicKeyPurpose{did.Authentication, did.AssertionMethod},
			}},
		}
		removeKeys := RemovePublicKeysAction{
			Action: RemovePublicKeys,
			IDs:    []string{"did:ion:test#key2"},
		}
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{addKeys, removeKeys})
		assert.Empty(tt, doc)
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "could not find key with id did:ion:test#key2")
	})

	t.Run("Add and remove keys patches - valid remove", func(tt *testing.T) {
		addKeys := AddPublicKeysAction{
			Action: AddPublicKeys,
			PublicKeys: []PublicKey{
				{
					ID:       "did:ion:test#key1",
					Purposes: []did.PublicKeyPurpose{did.Authentication, did.AssertionMethod},
				},
				{
					ID:       "did:ion:test#key2",
					Purposes: []did.PublicKeyPurpose{did.Authentication, did.AssertionMethod},
				},
			},
		}
		removeKeys := RemovePublicKeysAction{
			Action: RemovePublicKeys,
			IDs:    []string{"did:ion:test#key2"},
		}
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{addKeys, removeKeys})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, doc)
		assert.Len(tt, doc.VerificationMethod, 1)
		assert.Len(tt, doc.Authentication, 1)
		assert.Equal(tt, "did:ion:test#key1", doc.Authentication[0])
		assert.Len(tt, doc.AssertionMethod, 1)
		assert.Equal(tt, "did:ion:test#key1", doc.AssertionMethod[0])

		assert.Empty(tt, doc.KeyAgreement)
		assert.Empty(tt, doc.CapabilityDelegation)
		assert.Empty(tt, doc.CapabilityInvocation)
	})

	t.Run("Add and remove services", func(tt *testing.T) {
		addServices := AddServicesAction{
			Action: AddServices,
			Services: []did.Service{
				{
					ID:              "did:ion:test#service1",
					Type:            "test",
					ServiceEndpoint: "https://example.com",
				},
				{
					ID:              "did:ion:test#service2",
					Type:            "test",
					ServiceEndpoint: "https://example.com",
				},
			},
		}
		removeServices := RemoveServicesAction{
			Action: RemoveServices,
			IDs:    []string{"did:ion:test#service2"},
		}
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{addServices, removeServices})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, doc)
		assert.Empty(tt, doc.VerificationMethod)
		assert.Empty(tt, doc.Authentication)
		assert.Empty(tt, doc.AssertionMethod)
		assert.Empty(tt, doc.KeyAgreement)
		assert.Empty(tt, doc.CapabilityDelegation)
		assert.Empty(tt, doc.CapabilityInvocation)
		assert.Len(tt, doc.Services, 1)
		assert.Equal(tt, "did:ion:test#service1", doc.Services[0].ID)
	})

	t.Run("Replace patch", func(tt *testing.T) {
		replaceAction := ReplaceAction{
			Action: Replace,
			Document: Document{
				PublicKeys: []PublicKey{
					{
						ID:       "did:ion:test#key1",
						Purposes: []did.PublicKeyPurpose{did.Authentication, did.AssertionMethod},
					},
				},
				Services: []did.Service{
					{
						ID:              "did:ion:test#service1",
						Type:            "test",
						ServiceEndpoint: "https://example.com",
					},
				},
			},
		}
		doc, err := PatchesToDIDDocument("did:ion:test", "", []Patch{replaceAction})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, doc)
		assert.Len(tt, doc.VerificationMethod, 1)
		assert.Len(tt, doc.Authentication, 1)
		assert.Equal(tt, "did:ion:test#key1", doc.Authentication[0])
		assert.Len(tt, doc.AssertionMethod, 1)
		assert.Equal(tt, "did:ion:test#key1", doc.AssertionMethod[0])

		assert.Empty(tt, doc.KeyAgreement)
		assert.Empty(tt, doc.CapabilityDelegation)
		assert.Empty(tt, doc.CapabilityInvocation)

		assert.Len(tt, doc.Services, 1)
		assert.Equal(tt, "did:ion:test#service1", doc.Services[0].ID)
	})
}
