package flow

import (
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"log"
)

func Encrypt(stateJson []byte, enabledCondition func(config cryptoconfig.Config) bool) ([]byte, error) {
	primary, _, err := Configurations()
	if err != nil {
		log.Printf("[ERROR] failed to encrypt state because configuration was invalid, bailing out")
		log.Printf("[TRACE] state encryption configuration error was: %s", err)
		return stateJson, err
	}

	return encryptWithConfig(stateJson, primary, enabledCondition(primary))
}

func encryptWithConfig(stateJson []byte, config cryptoconfig.Config, enabled bool) ([]byte, error) {
	if enabled {
		candidate, err := attemptEncryption(stateJson, config)
		if err != nil {
			log.Printf("[TRACE] state encryption error was: %s", err)
			log.Printf("[ERROR] failed to encrypt state, bailing out")
			return []byte{}, err
		}
		log.Printf("[TRACE] successfully encrypted state, input %d bytes, output %d bytes", len(stateJson), len(candidate))
		return candidate, nil
	} else {
		log.Printf("[TRACE] no encryption configured, passing through state unchanged")
		return stateJson, nil
	}
}

func attemptEncryption(stateJson []byte, config cryptoconfig.Config) ([]byte, error) {
	stack, err := buildMethodStack(config)
	if err != nil {
		return stateJson, err
	}

	for _, method := range stack {
		stateJson, config, err = method.Encrypt(stateJson, config)
		if err != nil {
			return stateJson, err
		}
	}
	return stateJson, nil
}
