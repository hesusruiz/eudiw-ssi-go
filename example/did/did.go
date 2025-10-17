// A simple application using a did:key.
// To learn more about DIDs, please check out
// https://www.w3.org/TR/did-core/#did-document-properties
package main

import (
	"fmt"

	"github.com/hesusruiz/eudiw-ssi-go/crypto"
	"github.com/hesusruiz/eudiw-ssi-go/did/key"
	"github.com/hesusruiz/eudiw-ssi-go/example"
	"github.com/hesusruiz/eudiw-ssi-go/util"
)

func main() {
	// Create a did:key. This is a specific did using the "key" method
	// GenerateDIDKey takes in a key type value that this library supports and constructs a conformant did:key identifier.
	// To use the private key, it is recommended to re-cast to the associated type.
	// The function returns the associated private key value cast to the generic golang crypto.PrivateKey interface.
	// See more here: https://github.com/hesusruiz/eudiw-ssi-go/blob/9dfee15a66a94572c0aa77d97780c09728592201/did/key/key.go#L96
	_, didKey, err := key.GenerateDIDKey(crypto.SECP256k1)
	if err != nil {
		example.HandleExampleError(err, "failed to generate key")
	}

	// Expand the DID into a DID Document
	// Expanding is how did:key is resolved in the sdk
	// https://www.w3.org/TR/did-core/#did-document-properties
	didDoc, err := didKey.Expand()
	if err != nil {
		example.HandleExampleError(err, "failed to expand did:key")
	}

	// print it to stdout
	if dat, err := util.PrettyJSON(didDoc); err != nil {
		example.HandleExampleError(err, "failed to marshal did document")
	} else {
		// Some basic DID information printed out here.
		fmt.Printf("Generated DID document for did:key method:\n%s\n", string(dat))
	}
}
