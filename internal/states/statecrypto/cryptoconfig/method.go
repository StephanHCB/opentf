package cryptoconfig

// Method is the interface that must be implemented for a state encryption method.
//
// A stack of these methods is used to encrypt/decrypt the state payload before writing to or after
// reading from a local state file or the remote state backend.
//
// Note that the encrypted payload must still be valid json, because some remote state backends
// expect valid json.
//
// Also note that all implementations must gracefully handle unencrypted state being passed into Decrypt(),
// because this will inevitably happen when first encrypting previously unencrypted state. You should log a
// warning, though. As a consequence, you will need a way to recognize that you are looking at encrypted
// state vs. unencrypted state.
type Method interface {
	// Decrypt the state if encrypted, otherwise pass through unmodified.
	//
	// encryptedPayload is a json document passed in as a []byte.
	//
	// if you do not return an error, you must ensure you return a json document as a []byte
	// and a valid (potentially expanded) configuration that will be used for the next
	// method in the stack.
	Decrypt(payload []byte, configuration Config) ([]byte, Config, error)

	// Encrypt the plaintext state.
	//
	// plaintextPayload is a json document passed in as a []byte.
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
