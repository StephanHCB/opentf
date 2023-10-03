package flow

import (
	"fmt"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"log"
	"testing"
)

// configuration error cases

func configValidationErrorCase(t *testing.T, jsonConfig string, expectedError string) {
	config, err := parseConfig(jsonConfig)
	if err != nil {
		t.Fatal("error parsing configuration")
	}

	err = validateConfig(config)
	if err == nil {
		t.Errorf("unexpectedly got no error during config validation, expected '%s'", expectedError)
	}
	if err.Error() != expectedError {
		t.Errorf("got wrong error during instance creation '%s', expected '%s'", err.Error(), expectedError)
	}
}

const invalidConfigNoMethods = `{"encrypt_remote_state":true,"parameters":{"key":"a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1"}}`
const invalidConfigUnknownMethod = `{"methods":["something-unknown"],"parameters":{"key":"a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1"}}`

func TestCreation_invalidConfigNoMethods(t *testing.T) {
	configValidationErrorCase(t, invalidConfigNoMethods, "invalid configuration, must specify at least one method by name if encryption is turned on")
}

func TestCreation_invalidConfigUnknownMethod(t *testing.T) {
	configValidationErrorCase(t, invalidConfigUnknownMethod, "invalid configuration, encryption method 'something-unknown' is unknown")
}

// business scenarios

const validConfigWithKey1 = `{"encrypt_remote_state":true,"methods":["encrypt/AES256-CFB/SHA256"],"parameters":{"key":"a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1"}}`
const validConfigWithKey2 = `{"encrypt_remote_state":true,"methods":["encrypt/AES256-CFB/SHA256"],"parameters":{"key":"89346775897897a35892735ffd34723489734ee238748293741abcdef0123456"}}`
const validConfigWithKey3 = `{"encrypt_remote_state":true,"methods":["encrypt/AES256-CFB/SHA256"],"parameters":{"key":"33336775897897a35892735ffd34723489734ee238748293741abcdef0123456"}}`

const validConfigWithPassphrase1 = `{"encrypt_remote_state":true,"methods":["derive-key/PBKDF2/AES256","encrypt/AES256-CFB/SHA256"],"parameters":{"passphrase":"this is demo passphrase 1"}}`
const validConfigWithPassphrase2 = `{"encrypt_remote_state":true,"methods":["derive-key/PBKDF2/AES256","encrypt/AES256-CFB/SHA256"],"parameters":{"passphrase":"this is demo passphrase 2"}}`

const validPlaintext = `{"animals":[{"species":"cheetah","genus":"acinonyx"}]}`
const validEncryptedKey1 = `{"method":"encrypt/AES256-CFB/SHA256","payload":"e93e3e7ad3434055251f695865a13c11744b97e54cb7dee8f8fb40d1fb096b728f2a00606e7109f0720aacb15008b410cf2f92dd7989c2ff10b9712b6ef7d69ecdad1dccd2f1bddd127f0f0d87c79c3c062e03c2297614e2effa2fb1f4072d86df0dda4fc061"}`
const validEncryptedPassphrase1 = `{"method":"derive-key/PBKDF2/AES256","payload":{"method":"encrypt/AES256-CFB/SHA256","payload":"226ba6151c7751f2bd2ffcc2f666397f0cf8f6ea8ac2e336d7f3e07c8b8145f7e317f70a6bf4478b3c4469189ba1daccfe21ee76a88cbc66e460081d323b9344d5771b1a02ed7e477f69ad326c6c9d7d44d154b2e3d2c9b23fb34241be5cdcbdb4137321ddd2"},"salt":"a7da6b991820460619aaf1fb647ebde7"}`

const invalidConfigNoKey = `{"encrypt_remote_state":true,"methods":["encrypt/AES256-CFB/SHA256"],"parameters":{}}`

// TODO write test for these
const invalidConfigEncryptionNotLast = `{"encrypt_remote_state":true,"methods":["encrypt/AES256-CFB/SHA256","derive-key/PBKDF2/AES256"],"parameters":{"passphrase","this is a demo passphrase"}}`
const invalidConfigNoEncryption = `{"encrypt_remote_state":true,"methods":["derive-key/PBKDF2/AES256"],"parameters":{"passphrase","this is a demo passphrase"}}`

func compareSlices(got []byte, expected []byte) bool {
	eEmpty := len(expected) == 0
	gEmpty := len(got) == 0
	if eEmpty != gEmpty {
		return false
	}
	if eEmpty {
		return true
	}
	if len(expected) != len(got) {
		return false
	}
	for i, v := range expected {
		if v != got[i] {
			return false
		}
	}
	return true
}

func compareErrors(got error, expected string) string {
	if got != nil {
		if got.Error() != expected {
			return fmt.Sprintf("unexpected error '%s'; want '%s'", got.Error(), expected)
		}
	} else {
		if expected != "" {
			return fmt.Sprintf("did not get expected error '%s'", expected)
		}
	}
	return ""
}

type roundtripTestCase struct {
	name                  string
	description           string
	primaryConfiguration  string
	fallbackConfiguration string
	input                 string
	injectOutput          string
	expectedEncError      string
	expectedDecError      string
}

func TestEncryptDecrypt(t *testing.T) {
	// each test case first encrypts, then decrypts again
	testCases := []roundtripTestCase{
		// happy path cases - no encryption
		{
			name:        "no encryption",
			description: "unencrypted operation - no encryption configuration present, no fallback",
			input:       validPlaintext,
		},

		// happy path cases - AES256
		{
			name:                 "aes256 normal",
			description:          "normal operation on encrypted data - main configuration for aes256, no fallback",
			primaryConfiguration: validConfigWithKey1,
			input:                validPlaintext,
		},
		{
			name:                 "aes256 initial encrypt",
			description:          "initial encryption - main configuration for aes256, no fallback - prints a warning but must work anyway",
			primaryConfiguration: validConfigWithKey1,
			input:                validPlaintext,
			injectOutput:         validPlaintext,
		},
		{
			name:                  "aes256 decrypt",
			description:           "decryption - no main configuration, fallback aes256",
			fallbackConfiguration: validConfigWithKey1,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedKey1,
		},
		{
			name:                  "aes256 already decrypted",
			description:           "unencrypted operation with fallback still present (decryption edge case) - no encryption configuration present, fallback aes256 - prints a warning but must still work anyway",
			input:                 validPlaintext,
			fallbackConfiguration: validConfigWithKey1,
		},
		{
			name:                  "aes256 rotation",
			description:           "key rotation - main configuration for aes256 key 2, fallback aes256 key 1, read state with key 1 encryption - prints a warning but must work anyway",
			primaryConfiguration:  validConfigWithKey2,
			fallbackConfiguration: validConfigWithKey1,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedKey1,
		},
		{
			name:                  "aes256 already rotated",
			description:           "key rotation - main configuration for aes256 key 2, fallback aes256 key 1, read state with key 2 encryption",
			primaryConfiguration:  validConfigWithKey2,
			fallbackConfiguration: validConfigWithKey1,
			input:                 validPlaintext,
		},
		{
			name:                  "aes256 initial encrypt during rotation",
			description:           "initial encryption happens during key rotation (key rotation edge case) - main configuration for aes256 key 1, fallback for aes256 key 2 - prints a warning but must still work anyway",
			primaryConfiguration:  validConfigWithKey1,
			fallbackConfiguration: validConfigWithKey2,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validPlaintext,
		},

		// happy path cases - PBKDF2 + AES256
		{
			name:                 "pbkdf2 aes256 normal",
			description:          "normal operation on encrypted data - main configuration for pbkdf2_aes256, no fallback",
			primaryConfiguration: validConfigWithPassphrase1,
			input:                validPlaintext,
		},
		{
			name:                 "pbkdf2 aes256 initial encrypt",
			description:          "initial encryption - main configuration for pbkdf2_aes256, no fallback - prints a warning but must work anyway",
			primaryConfiguration: validConfigWithPassphrase1,
			input:                validPlaintext,
			injectOutput:         validPlaintext,
		},
		{
			name:                  "pbkdf2 aes256 decrypt",
			description:           "decryption - no main configuration, fallback pbkdf2_aes256",
			fallbackConfiguration: validConfigWithPassphrase1,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedPassphrase1,
		},
		{
			name:                  "pbkdf2 aes256 already decrypted",
			description:           "unencrypted operation with fallback still present (decryption edge case) - no encryption configuration present, fallback pbkdf2_aes256 - prints a warning but must still work anyway",
			input:                 validPlaintext,
			fallbackConfiguration: validConfigWithPassphrase1,
		},
		{
			name:                  "pbkdf2 aes256 rotation",
			description:           "key rotation for pbkdf2_aes256 - prints a warning but must work anyway",
			primaryConfiguration:  validConfigWithPassphrase2,
			fallbackConfiguration: validConfigWithPassphrase1,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedPassphrase1,
		},
		{
			name:                  "pbkdf2 aes256 already rotated",
			description:           "key rotation for pbkdf2_aes256 - already rotated state - read state with phrase 2 encryption",
			primaryConfiguration:  validConfigWithPassphrase2,
			fallbackConfiguration: validConfigWithPassphrase1,
			input:                 validPlaintext,
		},
		{
			name:                  "pbkdf2 aes256 initial encrypt during rotation",
			description:           "initial encryption happens during pbkdf2_aes256 key rotation (key rotation edge case) - prints a warning but must still work anyway",
			primaryConfiguration:  validConfigWithPassphrase1,
			fallbackConfiguration: validConfigWithPassphrase2,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validPlaintext,
		},
		{
			name:                  "aes256 to pbkdf2 aes256 switch",
			description:           "transparent switch from aes256 encryption to pbkdf2_aes256 - decryption using the fallback configuration - prints a warning but must still work anyway",
			primaryConfiguration:  validConfigWithPassphrase2,
			fallbackConfiguration: validConfigWithKey1,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedKey1,
		},

		// error cases - AES256
		{
			name:                 "aes256 wrong key",
			description:          "decryption fails due to wrong key - main configuration for aes256 key 3 - but state was encrypted with key 1",
			primaryConfiguration: validConfigWithKey3,
			input:                validPlaintext, // exact value irrelevant for this test case
			injectOutput:         validEncryptedKey1,
			expectedDecError:     "hash of decrypted payload did not match at position 0",
		},
		{
			name:                  "aes256 wrong fallback key",
			description:           "decryption fails due to wrong fallback key during decrypt lifecycle - no main configuration, fallback configuration for aes256 key 3 - but state was encrypted with key 1 - must fail and not use passthrough",
			fallbackConfiguration: validConfigWithKey3,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedKey1,
			expectedDecError:      "hash of decrypted payload did not match at position 0",
		},
		{
			name:                  "aes256 two wrong keys",
			description:           "decryption fails due to two wrong keys - main configuration for aes256 key 3, fallback for aes256 key 2 - but state was encrypted with key 1",
			primaryConfiguration:  validConfigWithKey3,
			fallbackConfiguration: validConfigWithKey2,
			input:                 validPlaintext, // exact value irrelevant for this test case
			injectOutput:          validEncryptedKey1,
			expectedDecError:      "hash of decrypted payload did not match at position 0",
		},

		// key error cases - AES256
		{
			name:                 "aes256 missing key",
			description:          "encryption fails due to missing key",
			primaryConfiguration: invalidConfigNoKey,
			input:                validPlaintext, // exact value irrelevant for this test case
			expectedEncError:     "configuration for AES256 needs the parameter 'key' set to a 32 byte lower case hexadecimal value",
			injectOutput:         validEncryptedKey1,
			expectedDecError:     "configuration for AES256 needs the parameter 'key' set to a 32 byte lower case hexadecimal value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			log.Printf("test case: %s: %s", tc.name, tc.description)
			primaryConfig, err := configFromString(tc.primaryConfiguration)
			if err != nil {
				t.Fatalf("error parsing main configuration: %s", err)
			}
			fallbackConfig, err := configFromString(tc.fallbackConfiguration)
			if err != nil {
				t.Fatalf("error parsing fallback configuration: %s", err)
			}
			roundtripTestcase(t, tc, primaryConfig, fallbackConfig)
		})
	}
}

func roundtripTestcase(t *testing.T, tc roundtripTestCase, primary cryptoconfig.Config, fallback cryptoconfig.Config) {
	encOutput, err := encryptWithConfig([]byte(tc.input), primary, primary.EncryptRemoteState)
	if comp := compareErrors(err, tc.expectedEncError); comp != "" {
		t.Error(comp)
	} else {
		if tc.injectOutput != "" {
			encOutput = []byte(tc.injectOutput)
		}

		decOutput, err := decryptWithConfigs(encOutput, primary, primary.EncryptRemoteState, fallback, fallback.EncryptRemoteState)
		if comp := compareErrors(err, tc.expectedDecError); comp != "" {
			t.Error(comp)
		} else {
			if err == nil && !compareSlices(decOutput, []byte(tc.input)) {
				t.Errorf("round trip error, got %#v; want %#v", decOutput, []byte(tc.input))
			}
		}
	}
}
