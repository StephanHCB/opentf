package sopsstate

import (
	"encoding/json"
	"fmt"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"testing"
)

const validKey1 = "a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1"

const validPlaintext = `{"animals":[{"species":"cheetah","genus":"acinonyx"}]}`

func conf(key string) cryptoconfig.Config {
	return cryptoconfig.Config{
		Methods: []string{
			Sops_Allvalues,
		},
		Parameters: map[string]string{
			"key": key,
		},
	}
}

func normalizeJson(doc []byte) string {
	asMap := make(map[string]interface{})
	err := json.Unmarshal(doc, &asMap)
	if err != nil {
		return fmt.Sprintf("cannot unmarshal: %s", err.Error())
	}

	normalized, err := json.Marshal(&asMap)
	if err != nil {
		return fmt.Sprintf("cannot marshal: %s", err.Error())
	}

	return string(normalized)
}

func TestRoundTrip(t *testing.T) {
	config := conf(validKey1)
	cut, _ := constructor(config, nil)

	// ... implementation is hard to maintain because needed internals are not exposed

	// would need a way to extract and manage the sops metadata separately - it's almost there, but not quite
	// insists on doing key management and there is no way to just provide the key

	encrypted, _, err := cut.Encrypt([]byte(validPlaintext), config)
	if err != nil {
		t.Error(err.Error())
	}

	// control over which fields to encrypt and which to leave plain is through prefixes and regexes,
	// not suitable to state, which gives us a list of sensitive fields

	decrypted, _, err := cut.Decrypt(encrypted, config)
	if err != nil {
		t.Error(err.Error())
	}

	// ... and it introduces different indentation, with unknown effects on systems working with state

	if normalizeJson(decrypted) != normalizeJson([]byte(validPlaintext)) {
		t.Error("did not match after roundtrip")
	}
}
