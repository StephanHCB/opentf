package cryptoconfig

// Config holds the configuration for transparent client-side state encryption
type Config struct {
	// EncryptRemoteState switches remote state encryption on if set to true
	EncryptRemoteState bool `json:"encrypt_remote_state"`

	// EncryptLocalState switches local state file encryption on if set to true
	EncryptLocalState bool `json:"encrypt_local_state"`

	// EncryptPlanFiles switches plan file encryption on if set to true
	EncryptPlanFiles bool `json:"encrypt_plan_files"`

	// Methods selects the methods to place in the encryption stack
	//
	// supported values are
	//   "encrypt/AES256-CFB/SHA256"
	//   "derive-key/PBKDF2/AES256"
	//   ... (see the constants at the top of each method implementation)
	//
	// supplying an unsupported value raises an error.
	//
	// If you supply a Config at all, this must not be empty.
	Methods []string `json:"methods"`

	// Parameters contains parameters, such as a key or passphrase, or a key vault URL.
	//
	// Each method has its own set of parameters, and each method can mutate the parameters for
	// the next method in the stack, or add parameters. This allows methods that perform key
	// management steps such as obtaining the encryption key from an external system, or converting
	// a pass phrase into an encryption key.
	Parameters map[string]string `json:"parameters"`
}

// ConfigEnvName configures the name of the environment variable used to configure encryption and decryption
//
// Set this environment variable to a json representation of Config, or leave it unset/blank
// to disable encryption (default behaviour).
var ConfigEnvName = "TF_STATE_ENCRYPTION"

// FallbackConfigEnvName configures the name of the environment variable used to configure fallback decryption
//
// Set this environment variable to a json representation of Config, or leave it unset/blank
// in order to not supply a fallback (default behaviour).
//
// Note that decryption will always try the configuration specified in TF_STATE_ENCRYPTION first.
// Only if decryption fails with that, it will try this configuration.
//
// Why is this useful?
// - key rotation (put the old key here until all state has been migrated)
// - decryption (leave TF_STATE_ENCRYPTION unset, but set this variable, and your state will be decrypted on next write)
var FallbackConfigEnvName = "TF_STATE_DECRYPTION_FALLBACK"
