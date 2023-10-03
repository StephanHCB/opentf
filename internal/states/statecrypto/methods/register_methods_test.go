package methods

import (
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"testing"
)

func TestRegisterMethods_DuplicateName(t *testing.T) {
	err := registerMethods(metadataValid, metadataValid)
	if err == nil || err.Error() != "duplicate state encryption method name in your metadata - this is an implementation bug" {
		t.Error("missing or wrong error")
	}
}

func TestMethodByName_Invalid(t *testing.T) {
	err := registerMethods(metadataInvalid)
	if err != nil {
		t.Error("unexpected error")
	}
	_, err = MethodByName("funny", cryptoconfig.Config{}, nil)
	if err == nil || err.Error() != "encryption method 'funny' does not define a constructor - this is an implementation bug" {
		t.Error("missing or wrong error")
	}
}

func metadataValid() cryptoconfig.MethodMetadata {
	return cryptoconfig.MethodMetadata{
		Name: "duplicate",
		Constructor: func(cryptoconfig.Config, cryptoconfig.Method) (cryptoconfig.Method, error) {
			return nil, nil
		},
	}
}

func metadataInvalid() cryptoconfig.MethodMetadata {
	return cryptoconfig.MethodMetadata{
		Name:        "funny",
		Constructor: nil,
	}
}
