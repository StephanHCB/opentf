package statecrypto

import "github.com/opentofu/opentofu/internal/states/statecrypto/flow"

func EncryptRemoteState(stateJson []byte) ([]byte, error) {
	return flow.Encrypt(stateJson, flow.EnabledForRemoteState)
}

func DecryptRemoteState(stateJson []byte) ([]byte, error) {
	return flow.Decrypt(stateJson, flow.EnabledForRemoteState)
}

func EncryptStateFile(stateJson []byte) ([]byte, error) {
	return flow.Encrypt(stateJson, flow.EnabledForLocalStateFile)
}

func DecryptStateFile(stateJson []byte) ([]byte, error) {
	return flow.Decrypt(stateJson, flow.EnabledForLocalStateFile)
}

func EncryptPlanFile(contents []byte) ([]byte, error) {
	return flow.Encrypt(contents, flow.EnabledForPlanFile)
}

func DecryptPlanFile(contents []byte) ([]byte, error) {
	return flow.Decrypt(contents, flow.EnabledForPlanFile)
}
