package pbkdf2aes256key

import (
	"bytes"
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
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload"`
	Salt    string          `json:"salt"`
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

func jsonToWrapper(raw []byte) *Pbkdf2Wrapper {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	result := &Pbkdf2Wrapper{}
	err := decoder.Decode(result)
	if err != nil {
		log.Print("[TRACE] failed to decode json input into Pbkdf2Wrapper, probably not encrypted - continuing")
		return nil
	}
	return result
}

func wrapperToJson(wrapper *Pbkdf2Wrapper) ([]byte, error) {
	return json.Marshal(wrapper)
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
	wrapper := jsonToWrapper(data)
	if wrapper == nil {
		log.Printf("[WARN] found state that was not encoded with this method, transparently reading it anyway")
		return data, config, nil
	}
	if wrapper.Method != Pbkdf2_Aes256key {
		// could be the primary configuration when fallback configuration is needed
		return data, config, fmt.Errorf("found state that was encoded with method %s, not %s", wrapper.Method, Pbkdf2_Aes256key)
	}

	passphrase, err := passphraseFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	salt, err := parseSalt(wrapper.Salt)
	if err != nil {
		return []byte{}, config, err
	}

	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha512.New)

	config.Parameters["key"] = encodeKey(key)

	return m.Next.Decrypt(wrapper.Payload, config)
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

	resultJson, err := wrapperToJson(&Pbkdf2Wrapper{
		Method:  Pbkdf2_Aes256key,
		Payload: encryptedPayload,
		Salt:    encodeSalt(salt),
	})

	return resultJson, config, err
}
