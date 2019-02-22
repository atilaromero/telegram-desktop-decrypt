package tdata

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
)

// TdataSettings reflects the streams contained in the tdata/settings0 file.
type TdataSettings struct {
	Salt      []byte
	Encrypted []byte
}

// ReadTdataSettings opens the tdata/settings0 or tdata/settings1
func ReadTdataSettings(f io.Reader) (TdataSettings, error) {
	result := TdataSettings{}
	tfile, err := ReadFile(f)
	if err != nil {
		return result, fmt.Errorf("could not interpret file, error: %v", err)
	}
	streams, err := ReadQtStreams(tfile.Data)
	if err != nil {
		return result, fmt.Errorf("could not read streams: %v", err)
	}
	result.Salt = streams[0]
	result.Encrypted = streams[1]
	return result, err
	// fmt.Printf("settingsKey (%d):\n", len(settingsKey))
	// fmt.Println(hex.EncodeToString(settingsKey[:]))
}
func (settings TdataSettings) GetKey(password string) []byte {
	settingsKey := decrypt.CreateLocalKey([]byte(password), settings.Salt)
	return settingsKey
}
func (settings TdataSettings) Decrypt(settingsKey []byte) ([]byte, error) {
	decrypted, err := decrypt.DecryptLocal(settings.Encrypted, settingsKey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt settings file: %v", err)
	}
	return decrypted, nil
}

func (settings TdataSettings) Print() {
	fmt.Printf("salt\t%s\n", hex.EncodeToString(settings.Salt))
	fmt.Printf("encrypted\t%s\n", hex.EncodeToString(settings.Encrypted))
}
