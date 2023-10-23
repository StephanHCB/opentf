package methods

import (
	"errors"
	"fmt"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	aes256state "github.com/opentofu/opentofu/internal/states/statecrypto/methods/aes256-cfb-sha256"
	gocloud_secrets "github.com/opentofu/opentofu/internal/states/statecrypto/methods/gocloud-secrets"
	pbkdf2aes256key "github.com/opentofu/opentofu/internal/states/statecrypto/methods/pbkdf2-passphrase-to-aes256key"
	"log"
)

// EnsureMethodsRegistered is where registration of state encryption methods takes place.
//
// Important: do not expose your StateCryptoMethodMetadata as a variable, instead provide a function
// called Metadata() that returns it. This prevents malicious dependencies from injecting validation
// functions that steal your key.
//
// This is why we force you to write a function that returns it.
func EnsureMethodsRegistered() {
	if methodMetadata != nil {
		return
	}

	err := registerMethods(
		aes256state.Metadata,
		pbkdf2aes256key.Metadata,
		gocloud_secrets.Metadata,
		// register other encryption/key derivation methods here
	)

	if err != nil {
		log.Fatalf("[ERROR] error during registration of state encryption methods - this is an implementation error. Error was: %s", err)
	}
}

var methodMetadata map[string]cryptoconfig.MethodMetadata

func registerMethods(methodsToRegister ...func() cryptoconfig.MethodMetadata) error {
	methodMetadata = make(map[string]cryptoconfig.MethodMetadata)

	for _, metadataFunc := range methodsToRegister {
		metadata := metadataFunc()
		if _, exists := methodMetadata[metadata.Name]; exists {
			return errors.New("duplicate state encryption method name in your metadata - this is an implementation bug")
		}
		methodMetadata[metadata.Name] = metadata
	}

	return nil
}

func MethodByName(name string, config cryptoconfig.Config, next cryptoconfig.Method) (cryptoconfig.Method, error) {
	metadata, ok := methodMetadata[name]
	if !ok {
		return nil, fmt.Errorf("invalid configuration, encryption method '%s' is unknown", name)
	}
	if metadata.Constructor == nil {
		return nil, fmt.Errorf("encryption method '%s' does not define a constructor - this is an implementation bug", name)
	}
	return metadata.Constructor(config, next)
}
