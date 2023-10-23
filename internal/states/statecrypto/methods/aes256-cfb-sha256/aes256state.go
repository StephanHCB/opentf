package aes256state

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"io"
	"log"
	"regexp"
)

const ClientSide_Aes256cfb_Sha256 = "encrypt/AES256-CFB/SHA256"

func Metadata() cryptoconfig.MethodMetadata {
	return cryptoconfig.MethodMetadata{
		Name:        ClientSide_Aes256cfb_Sha256,
		Constructor: constructor,
	}
}

func constructor(configuration cryptoconfig.Config, next cryptoconfig.Method) (cryptoconfig.Method, error) {
	if next != nil {
		return nil, fmt.Errorf("invalid configuration, %s must be used last in the list of methods", ClientSide_Aes256cfb_Sha256)
	}
	return &AES256CFBMethod{}, nil
}

type AES256CFBMethod struct {
}

func parseKey(hexKey string) ([]byte, error) {
	validator := regexp.MustCompile("^[0-9a-f]{64}$")
	if !validator.MatchString(hexKey) {
		return []byte{}, fmt.Errorf("key was not a hex string representing 32 bytes, must match [0-9a-f]{64}")
	}

	key, _ := hex.DecodeString(hexKey)

	return key, nil
}

func parseKeyFromConfiguration(config cryptoconfig.Config) ([]byte, error) {
	hexkey, ok := config.Parameters["key"]
	if !ok {
		return []byte{}, fmt.Errorf("configuration for AES256 needs the parameter 'key' set to a 32 byte lower case hexadecimal value")
	}

	key, err := parseKey(hexkey)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}

type Aes256CfbWrapper struct {
	Encryption cryptoconfig.EncryptionInfo `json:"encryption"`
	Payload    string                      `json:"payload"`
}

func jsonToWrapper(raw []byte) (*Aes256CfbWrapper, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	result := &Aes256CfbWrapper{}
	err := decoder.Decode(result)
	if err != nil {
		log.Print("[TRACE] failed to decode json input into Aes256CfbWrapper, probably not encrypted, or not with this method")
	}
	return result, err
}

func (a *AES256CFBMethod) decodeFromEncryptedJsonWithChecks(jsonCryptedData []byte) ([]byte, error) {
	wrapper, err := jsonToWrapper(jsonCryptedData)
	if err != nil {
		log.Printf("[TRACE] found state that was not encoded with this method, failing")
		return []byte{}, fmt.Errorf("found state that was not encrypted with %s, failing", ClientSide_Aes256cfb_Sha256)
	}
	_, ok := wrapper.Encryption.Methods[ClientSide_Aes256cfb_Sha256]
	if !ok {
		return []byte{}, fmt.Errorf("found state that was not encrypted with %s, failing", ClientSide_Aes256cfb_Sha256)
	}

	if len(wrapper.Payload)%2 != 0 {
		return []byte{}, errors.New("ciphertext contains odd number of characters, possibly cut off or garbled")
	}

	ciphertext := make([]byte, hex.DecodedLen(len(wrapper.Payload)))
	n, err := hex.Decode(ciphertext, []byte(wrapper.Payload))
	if err != nil {
		log.Printf("[TRACE] ciphertext contains invalid characters: %s", err.Error())
		return []byte{}, errors.New("ciphertext contains invalid characters, possibly cut off or garbled")
	}
	if n != hex.DecodedLen(len(wrapper.Payload)) {
		return []byte{}, fmt.Errorf("did not fully decode, only read %d characters before encountering an error", n)
	}
	return ciphertext, nil
}

func (a *AES256CFBMethod) encodeToEncryptedJson(ciphertext []byte) []byte {
	encryptedHex := make([]byte, hex.EncodedLen(len(ciphertext)))
	_ = hex.Encode(encryptedHex, ciphertext)

	encryptionInfo := cryptoconfig.EncryptionInfo{
		Version: 1,
		Methods: make(map[string]interface{}),
	}
	encryptionInfo.Methods[ClientSide_Aes256cfb_Sha256] = make(map[string]interface{})

	wrapper := &Aes256CfbWrapper{
		Encryption: encryptionInfo,
		Payload:    string(encryptedHex),
	}
	result, _ := json.Marshal(wrapper)
	return result
}

func (a *AES256CFBMethod) attemptDecryption(jsonCryptedData []byte, key []byte) ([]byte, error) {
	ciphertext, err := a.decodeFromEncryptedJsonWithChecks(jsonCryptedData)
	if err != nil {
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	if len(ciphertext) < aes.BlockSize {
		return []byte{}, fmt.Errorf("ciphertext too short, did not contain initial vector")
	}
	iv := ciphertext[:aes.BlockSize]
	payloadWithHash := ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(payloadWithHash, payloadWithHash)

	plaintextPayload := payloadWithHash[:len(payloadWithHash)-sha256.Size]
	hashRead := payloadWithHash[len(payloadWithHash)-sha256.Size:]

	hashComputed := sha256.Sum256(plaintextPayload)
	for i, v := range hashComputed {
		if v != hashRead[i] {
			return []byte{}, fmt.Errorf("hash of decrypted payload did not match at position %d", i)
		}
	}

	// payloadWithHash is now decrypted
	return plaintextPayload, nil
}

func (a *AES256CFBMethod) attemptEncryption(plaintextPayload []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintextPayload)+sha256.Size)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	// add hash over plaintext to end of plaintext (allows integrity check when decrypting)
	hashArray := sha256.Sum256(plaintextPayload)
	plaintextWithHash := append(plaintextPayload, hashArray[0:sha256.Size]...)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextWithHash)

	return a.encodeToEncryptedJson(ciphertext), nil
}

// Encrypt data (which is a []byte containing a json structure) into a json structure.
//
// fail if encryption is not possible to prevent writing unencrypted state
func (a *AES256CFBMethod) Encrypt(plaintextPayload []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	key, err := parseKeyFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	encrypted, err := a.attemptEncryption(plaintextPayload, key)
	if err != nil {
		return []byte{}, config, err
	}
	return encrypted, config, nil
}

// Decrypt the contents of data.
//
// fail if data does not have the expected format
func (a *AES256CFBMethod) Decrypt(data []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	key, err := parseKeyFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	candidate, err := a.attemptDecryption(data, key)
	if err != nil {
		return []byte{}, config, err
	}
	return candidate, config, nil
}
