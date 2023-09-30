package flow

import (
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"log"
)

func Decrypt(stateJson []byte, enabledCondition func(config cryptoconfig.Config) bool) ([]byte, error) {
	primary, fallback, err := Configurations()
	if err != nil {
		log.Printf("[ERROR] failed to decrypt state because configuration was invalid, bailing out")
		log.Printf("[TRACE] state decryption configuration error was: %s", err)
		return stateJson, err
	}

	return decryptWithConfigs(stateJson, primary, enabledCondition(primary), fallback, enabledCondition(fallback))
}

func decryptWithConfigs(
	stateJson []byte,
	primary cryptoconfig.Config,
	primaryEnabled bool,
	fallback cryptoconfig.Config,
	fallbackEnabled bool,
) ([]byte, error) {
	if primaryEnabled {
		candidate, err := attemptDecryption(stateJson, primary)
		if err != nil {
			if fallbackEnabled {
				log.Printf("[TRACE] failed to decrypt state with primary configuration, now trying fallback. Error for primary was: %s", err)
				candidate2, err2 := attemptDecryption(stateJson, fallback)
				if err2 != nil {
					log.Printf("[TRACE] failed to decrypt state with fallback configuration. Error for fallback was: %s", err)
					log.Printf("[ERROR] failed to decrypt state with both primary and fallback configuration, bailing out")
					return []byte{}, err2
				}
				log.Printf("[TRACE] successfully decrypted state using fallback configuration, input %d bytes, output %d bytes", len(stateJson), len(candidate2))
				return candidate2, nil
			} else {
				log.Printf("[TRACE] failed to decrypt state with primary configuration. Error for primary was: %s", err)
				log.Printf("[ERROR] failed to decrypt state with primary configuration and no fallback configured, bailing out")
				return []byte{}, err
			}
		}
		log.Printf("[TRACE] successfully decrypted state using primary configuration, input %d bytes, output %d bytes", len(stateJson), len(candidate))
		return candidate, nil
	} else if fallbackEnabled {
		candidate, err := attemptDecryption(stateJson, fallback)
		if err != nil {
			log.Printf("[TRACE] failed to decrypt state with fallback configuration (no primary configured). Error for fallback was: %s", err)
			log.Printf("[ERROR] failed to decrypt state with fallback configuration and no primary configuration available, bailing out")
			return []byte{}, err
		}
		log.Printf("[TRACE] successfully decrypted state using fallback configuration (no primary configured), input %d bytes, output %d bytes", len(stateJson), len(candidate))
		return candidate, nil
	} else {
		log.Printf("[TRACE] no decryption configured, passing through state unchanged")
		return stateJson, nil
	}

}

func attemptDecryption(stateJson []byte, config cryptoconfig.Config) ([]byte, error) {
	stack, err := buildMethodStack(config)
	if err != nil {
		return stateJson, err
	}

	for _, method := range stack {
		stateJson, config, err = method.Decrypt(stateJson, config)
		if err != nil {
			return stateJson, err
		}
	}
	return stateJson, nil
}
