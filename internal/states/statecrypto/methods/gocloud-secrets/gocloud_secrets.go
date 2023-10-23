package gocloud_secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"        // support for awskms://
	_ "gocloud.dev/secrets/azurekeyvault" // support for azurekeyvault://
	_ "gocloud.dev/secrets/gcpkms"        // support for gcpkms://
	_ "gocloud.dev/secrets/hashivault"    // support for hashivault://
	"log"
	"regexp"
)

const GocloudSecrets_AES256Key = "derive-key/Gocloud-Secrets/AES256key"

func Metadata() cryptoconfig.MethodMetadata {
	return cryptoconfig.MethodMetadata{
		Name:        GocloudSecrets_AES256Key,
		Constructor: constructor,
	}
}

func constructor(configuration cryptoconfig.Config, next cryptoconfig.Method) (cryptoconfig.Method, error) {
	if next == nil {
		return nil, fmt.Errorf("invalid configuration, %s is a key derivation method and cannot be last in the list of methods. It must be followed by an encryption method", GocloudSecrets_AES256Key)
	}
	return &GocloudSecretsMethod{
		Next: next,
	}, nil
}

type GocloudSecretsMethod struct {
	Next cryptoconfig.Method
}

type GocloudSecretsWrapper struct {
	Encryption cryptoconfig.EncryptionInfo `json:"encryption"`
}

func openKeeper(configuration cryptoconfig.Config) (*secrets.Keeper, func(), error) {
	nothingFunc := func() {}

	secretUrl, ok := configuration.Parameters["gocloud-secrets-url"]
	if !ok {
		return nil, nothingFunc, fmt.Errorf("must configure parameter gocloud-secrets-url, see https://gocloud.dev/howto/secrets/")
	}

	keeper, err := secrets.OpenKeeper(context.Background(), secretUrl)
	if err != nil {
		return nil, nothingFunc, err
	}

	closeFunc := func() {
		if err := keeper.Close(); err != nil {
			// TODO LOG
		}
	}
	return keeper, closeFunc, nil
}

func encodeKey(raw []byte) string {
	return hex.EncodeToString(raw)
}

func extractSalt(rawJson []byte) (string, error) {
	wrapper := GocloudSecretsWrapper{}
	err := json.Unmarshal(rawJson, &wrapper)
	if err != nil {
		log.Print("[TRACE] failed to decode json input into GocloudSecretsWrapper, probably not encrypted")
		return "", fmt.Errorf("found state that was not encrypted with %s", GocloudSecrets_AES256Key)
	}

	methodInfoRaw, ok := wrapper.Encryption.Methods[GocloudSecrets_AES256Key]
	if !ok {
		log.Printf("[TRACE] failed to find %s among methods", GocloudSecrets_AES256Key)
		return "", fmt.Errorf("found state that was not encrypted with %s", GocloudSecrets_AES256Key)
	}
	methodInfo, ok := methodInfoRaw.(map[string]interface{})
	if !ok {
		log.Printf("[TRACE] failed to convert methods to json object")
		return "", fmt.Errorf("found state that was not encrypted with %s", GocloudSecrets_AES256Key)
	}
	saltRaw, ok := methodInfo["salt"]
	if !ok {
		log.Printf("[TRACE] field 'salt' not present")
		return "", fmt.Errorf("found no salt in state")
	}
	saltHex, ok := saltRaw.(string)
	if !ok {
		log.Printf("[TRACE] field 'salt' was not of type string")
		return "", fmt.Errorf("found no salt in state")
	}

	return saltHex, nil
}

func parseSalt(hexValue string) ([]byte, error) {
	validator := regexp.MustCompile("^[0-9a-f]{32}$")
	if !validator.MatchString(hexValue) {
		return []byte{}, fmt.Errorf("salt was not a hex string representing 16 bytes, must match [0-9a-f]{32}")
	}

	salt, err := hex.DecodeString(hexValue)
	return salt, err
}

func encodeSalt(raw []byte) string {
	return hex.EncodeToString(raw)
}

func wrapWithSaltAsJson(saltHex string, payload []byte) ([]byte, error) {
	everything := make(map[string]interface{})
	err := json.Unmarshal(payload, &everything)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decode full input to wrap")
	}

	wrapper := GocloudSecretsWrapper{}
	err = json.Unmarshal(payload, &wrapper)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decode encryption info input to wrap")
	}

	if wrapper.Encryption.Methods == nil {
		wrapper.Encryption.Methods = make(map[string]interface{})
	}
	wrapper.Encryption.Methods[GocloudSecrets_AES256Key] = map[string]interface{}{
		"salt": saltHex,
	}

	everything["encryption"] = wrapper.Encryption

	return json.Marshal(everything)
}

func (m *GocloudSecretsMethod) Decrypt(data []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	keeper, closeKeeper, err := openKeeper(config)
	defer closeKeeper()

	saltStr, err := extractSalt(data)
	if err != nil {
		return []byte{}, config, err
	}

	encryptedDataKey, err := parseSalt(saltStr)
	if err != nil {
		return []byte{}, config, err
	}

	// check length

	plaintextDataKey, err := keeper.Decrypt(context.Background(), encryptedDataKey)
	if err != nil {
		return []byte{}, config, err
	}

	config.Parameters["key"] = encodeKey(plaintextDataKey)

	return m.Next.Decrypt(data, config)
}

func (m *GocloudSecretsMethod) Encrypt(data []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	keeper, closeKeeper, err := openKeeper(config)
	defer closeKeeper()

	// create a new salt
	plaintextDataKey := make([]byte, 32)
	_, err = rand.Read(plaintextDataKey)
	if err != nil {
		return []byte{}, config, err
	}

	config.Parameters["key"] = encodeKey(plaintextDataKey)

	encryptedDataKey, err := keeper.Encrypt(context.Background(), plaintextDataKey)

	encryptedPayload, _, err := m.Next.Encrypt(data, config)
	if err != nil {
		return []byte{}, config, err
	}

	resultJson, err := wrapWithSaltAsJson(encodeSalt(encryptedDataKey), encryptedPayload)

	return resultJson, config, err
}
