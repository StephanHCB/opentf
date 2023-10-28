package sopsstate

import (
	"encoding/hex"
	"fmt"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/version"
	"github.com/opentofu/opentofu/internal/states/statecrypto/cryptoconfig"
	"regexp"
	"time"
)

const Sops_Allvalues = "encrypt/sops/allvalues"

func Metadata() cryptoconfig.MethodMetadata {
	return cryptoconfig.MethodMetadata{
		Name:        Sops_Allvalues,
		Constructor: constructor,
	}
}

func constructor(configuration cryptoconfig.Config, next cryptoconfig.Method) (cryptoconfig.Method, error) {
	if next != nil {
		return nil, fmt.Errorf("invalid configuration, %s must be used last in the list of methods", Sops_Allvalues)
	}
	return &SOPSMethod{}, nil
}

type SOPSMethod struct {
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

func (a *SOPSMethod) Encrypt(plaintextPayload []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	aesKey, err := parseKeyFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	inputStore := &json.Store{}

	treeBranches, err := inputStore.LoadPlainFile(plaintextPayload)
	if err != nil {
		return []byte{}, config, err
	}

	// following cmd/sops/encrypt.go encrypt()

	// here, we need to construct metadata manually

	tree := sops.Tree{
		Metadata: sops.Metadata{
			UnencryptedSuffix: "",
			EncryptedSuffix:   "",
			UnencryptedRegex:  "",
			EncryptedRegex:    "",
			Version:           version.Version,
		},
		Branches: treeBranches,
		FilePath: "OpenTofu-state-not-a-file.json",
	}

	cipher := aes.NewCipher()
	unencryptedMac, err := tree.Encrypt(aesKey, cipher)
	if err != nil {
		return []byte{}, config, err
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(unencryptedMac, aesKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return []byte{}, config, err
	}

	// end following cmd/sops/encrypt.go encrypt()

	outputStore := &json.Store{}
	encrypted, err := outputStore.EmitEncryptedFile(tree)

	return encrypted, config, nil
}

func (a *SOPSMethod) Decrypt(data []byte, config cryptoconfig.Config) ([]byte, cryptoconfig.Config, error) {
	aesKey, err := parseKeyFromConfiguration(config)
	if err != nil {
		return []byte{}, config, err
	}

	inputStore := &json.Store{}

	//tree, err := inputStore.LoadEncryptedFile(data)
	//if err != nil {
	//	return []byte{}, config, err
	//}
	//
	// if not also using SOPS key mgmt, this errors out "no keys found in file"
	//
	// TODO add SOPS based key mgmt (requires one of GPG, AGE, or any of the 4 Vault projects)

	// TMP need to cut the sops part out and construct metadata from it manually :(
	treeBranches, err := inputStore.LoadPlainFile(data)
	// TMP extract metadata from file by hand for the moment
	tempMetadata := sops.Metadata{
		UnencryptedSuffix: "",
		EncryptedSuffix:   "",
		UnencryptedRegex:  "",
		EncryptedRegex:    "",
	}
	for bi, branch := range treeBranches {
		for s, sectionBranch := range branch {
			if sectionBranch.Key == "sops" {
				items, ok := sectionBranch.Value.(sops.TreeBranch)
				if ok {
					for _, item := range items {
						if item.Key == "mac" {
							tempMetadata.MessageAuthenticationCode = item.Value.(string)
						}
						if item.Key == "version" {
							tempMetadata.Version = item.Value.(string)
						}
						if item.Key == "lastmodified" {
							lastModified, err := time.Parse(time.RFC3339, item.Value.(string))
							if err != nil {
								return []byte{}, config, err
							}
							tempMetadata.LastModified = lastModified
						}
					}
				}

				branch = append(branch[:s], branch[s+1:]...)
				treeBranches[bi] = branch
			}
		}
	}
	tree := sops.Tree{
		Metadata: tempMetadata,
		Branches: treeBranches,
		FilePath: "OpenTofu-state-not-a-file.json",
	}

	// following decrypt/decrypt.go DataWithFormat(), but we want to manage keys ourselves for now

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(aesKey, cipher)
	if err != nil {
		if err != nil {
			return []byte{}, config, err
		}
	}

	// Compute the hash of the cleartext tree and compare it with
	// the one that was stored in the document. If they match,
	// integrity was preserved
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		aesKey,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return []byte{}, config, fmt.Errorf("Failed to decrypt original mac: %w", err)
	}
	if originalMac != mac {
		return []byte{}, config, fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}

	// end following decrypt/decrypt.go DataWithFormat()

	outputStore := &json.Store{}
	cleartext, err := outputStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return []byte{}, config, err
	}

	return cleartext, config, nil
}
