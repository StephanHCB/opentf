package cryptoconfig

// Method is the interface that must be implemented for a state encryption method.
//
// A stack of these methods is used to encrypt/decrypt the state payload before writing to or after
// reading from a local state file or the remote state backend.
//
// Note that the encrypted payload must still be valid json, because some remote state backends
// expect valid json.
type Method interface {
	// Decrypt the state or plan.
	//
	// payload is a json document passed in as a []byte.
	//
	// if you do not return an error, you must ensure you return a json document as a []byte
	// and a valid (potentially expanded) configuration that will be used for the next
	// method in the stack.
	Decrypt(payload []byte, configuration Config) ([]byte, Config, error)

	// Encrypt the plaintext state or plan.
	//
	// payload is a json document passed in as a []byte.
	//
	// if you do not return an error, you must ensure you return a json document as
	// a []byte, because some remote state storage backends rely on this,
	// and a valid (potentially expanded) configuration that will be used for the next
	// method in the stack.
	Encrypt(payload []byte, configuration Config) ([]byte, Config, error)
}

// MethodMetadata provides the configuration parser with information about
// which parameters a method expects and how to validate the parameters.
//
// Each state encryption method should implement a Metadata() function that returns this.
type MethodMetadata struct {
	// Name is the name of the method, to be listed under methods in the configuration.
	Name string

	// Constructor should return a ready-to-go instance of your Method.
	//
	// You can reject invalid configurations here, but if you want another method to be
	// able to provide a configuration value, then you should not check it during the construction phase.
	// Example: it would be wrong to check that the configuration provides the encryption key,
	// because that may be provided by a method further up in the stack.
	//
	// nextInStack is the next method in the stack, or nil if this method is the last
	// in the stack. If your method expects to be the last in the stack, you should
	// return an error if nextInStack is not nil. Similarly, if your method is for key derivation,
	// you should return a meaningful error if nextInStack is nil.
	Constructor func(configuration Config, nextInStack Method) (Method, error)
}

// EncryptionInfo is added to encrypted state or plans under "encryption".
type EncryptionInfo struct {
	// Version is currently always 1.
	Version int `json:"version"`

	// Methods tracks which methods were used to encrypt this state or plan. The values are
	// method dependent.
	Methods map[string]interface{} `json:"methods"`
}
