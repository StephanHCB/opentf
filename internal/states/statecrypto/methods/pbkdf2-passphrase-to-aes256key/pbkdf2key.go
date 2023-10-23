package pbkdf2aes256key

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"regexp"
)

const Pbkdf2_Aes256key = "derive-key/PBKDF2/AES256"

func Metadata() cryptoconfig.MethodMetadata {
	return cryptoconfig.MethodMetadata{
		Name:        Pbkdf2_Aes256key,
		Constructor: constructor,
	}
}

func constructor(configuration cryptoconfig.Config, next cryptoconfig.Method) (cryptoconfig.Method, error) {
	if next == nil {
		return nil, fmt.Errorf("invalid configuration, %s is a key derivation method and cannot be last in the list of methods. It must be followed by an encryption method", Pbkdf2_Aes256key)
	}
	return &Pbkdf2Method{
		Next: next,
	}, nil
}

type Pbkdf2Method struct {
	Next cryptoconfig.Method
}

type Pbkdf2Wrapper struct {
	Encryption cryptoconfig.EncryptionInfo `json:"encryption"`
}

func passphraseFromConfiguration(config cryptoconfig.Config) (string, error) {
	passphrase, ok := config.Parameters["passphrase"]
	if !ok {
		return "", fmt.Errorf("configuration for PBKDF2 needs the parameter 'passphrase' set to your passphrase")
	}

	if len(passphrase) == 0 {
		return "", fmt.Errorf("configuration invalid, parameter 'passphrase' must not be empty")
	}

	return passphrase, nil
}

func extractSalt(rawJson []byte) (string, error) {
	wrapper := Pbkdf2Wrapper{}
	err := json.Unmarshal(rawJson, &wrapper)
	if err != nil {
		log.Print("[TRACE] failed to decode json input into Pbkdf2Wrapper, probably not encrypted")
		return "", fmt.Errorf("found state that was not encrypted with %s", Pbkdf2_Aes256key)
	}

	methodInfoRaw, ok := wrapper.Encryption.Methods[Pbkdf2_Aes256key]
	if !ok {
		log.Printf("[TRACE] failed to find %s among methods", Pbkdf2_Aes256key)
		return "", fmt.Errorf("found state that was not encrypted with %s", Pbkdf2_Aes256key)
	}
	methodInfo, ok := methodInfoRaw.(map[string]interface{})
	if !ok {
		log.Printf("[TRACE] failed to convert methods to json object")
		return "", fmt.Errorf("found state that was not encrypted with %s", Pbkdf2_Aes256key)
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

func wrapWithSaltAsJson(saltHex string, payload []byte) ([]byte, error) {
	everything := make(map[string]interface{})
	err := json.Unmarshal(payload, &everything)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decode full input to wrap")
	}

	wrapper := Pbkdf2Wrapper{}
	err = json.Unmarshal(payload, &wrapper)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decode encryption info input to wrap")
	}

	if wrapper.Encryption.Methods == nil {
		wrapper.Encryption.Methods = make(map[string]interface{})
	}
	wrapper.Encryption.Methods[Pbkdf2_Aes256key] = map[string]interface{}{
		"salt": saltHex,
	}

	everything["encryption"] = wrapper.Encryption

	return json.Marshal(everything)
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

func encodeKey(raw []byte) string {
	return hex.EncodeToString(raw)
}

func (m *Pbkdf2Method) Decrypt(data []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	saltStr, err := extractSalt(data)
	if err != nil {
		return []byte{}, config, err
	}

	passphrase, err := passphraseFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	salt, err := parseSalt(saltStr)
	if err != nil {
		return []byte{}, config, err
	}

	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha512.New)

	config.Parameters["key"] = encodeKey(key)

	return m.Next.Decrypt(data, config)
}

func (m *Pbkdf2Method) Encrypt(data []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	passphrase, err := passphraseFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return []byte{}, config, fmt.Errorf("could not generate salt: %w", err)
	}

	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha512.New)

	config.Parameters["key"] = encodeKey(key)

	encryptedPayload, _, err := m.Next.Encrypt(data, config)
	if err != nil {
		return []byte{}, config, err
	}

	resultJson, err := wrapWithSaltAsJson(encodeSalt(salt), encryptedPayload)

	return resultJson, config, err
}
