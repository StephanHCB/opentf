package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"github.com/opentofu/opentofu/internal/states/statecrypto/methods"
	"os"
)

func Configurations() (primary cryptoconfig.Config, fallback cryptoconfig.Config, err error) {
	primary, err = configFromEnv(cryptoconfig.ConfigEnvName)
	if err != nil {
		return
	}
	fallback, err = configFromEnv(cryptoconfig.FallbackConfigEnvName)
	return
}

func EnabledForRemoteState(config cryptoconfig.Config) bool {
	return config.EncryptRemoteState
}

func EnabledForLocalStateFile(config cryptoconfig.Config) bool {
	return config.EncryptLocalState
}

func EnabledForPlanFile(config cryptoconfig.Config) bool {
	return config.EncryptPlanFiles
}

// buildMethodStack builds the stack of methods from the configuration using the
// constructor functions defined in the metadata of the listed methods.
//
// This will typically also validate static parameters, but not dynamic parameters such as keys.
func buildMethodStack(config cryptoconfig.Config) (current cryptoconfig.Method, err error) {
	for i := len(config.Methods) - 1; i >= 0; i-- {
		current, err = methods.MethodByName(config.Methods[i], config, current)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func configFromEnv(envName string) (cryptoconfig.Config, error) {
	return configFromString(os.Getenv(envName))
}

func configFromString(envValue string) (cryptoconfig.Config, error) {
	config, err := parseConfig(envValue)
	if err != nil {
		return cryptoconfig.Config{}, err
	}

	if err := validateConfig(config); err != nil {
		return cryptoconfig.Config{}, err
	}
	return config, nil
}

func parseConfig(jsonConfig string) (cryptoconfig.Config, error) {
	if jsonConfig == "" {
		return cryptoconfig.Config{}, nil
	}

	config := cryptoconfig.Config{}

	dec := json.NewDecoder(bytes.NewReader([]byte(jsonConfig)))
	dec.DisallowUnknownFields()
	err := dec.Decode(&config)

	return config, err
}

func validateConfig(config cryptoconfig.Config) error {
	methods.EnsureMethodsRegistered()

	if len(config.Methods) == 0 && (config.EncryptRemoteState || config.EncryptLocalState || config.EncryptPlanFiles) {
		return errors.New("invalid configuration, must specify at least one method by name if encryption is turned on")
	}

	_, err := buildMethodStack(config)
	return err
}
