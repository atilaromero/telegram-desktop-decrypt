package encrypted

import (
	"encoding/hex"
	"fmt"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
	"github.com/atilaromero/telegram-desktop-decrypt/qt"
	"github.com/atilaromero/telegram-desktop-decrypt/tdata"
)

// ESettings reflects the streams contained in the tdata/settings0 file.
type ESettings struct {
	Salt      []byte
	Encrypted []byte
}

// ReadESettings opens the tdata/settings0 or tdata/settings1
func ReadESettings(tfile tdata.RawTDF) (ESettings, error) {
	result := ESettings{}
	streams, err := qt.ReadStreams(tfile.Data)
	if err != nil {
		return result, fmt.Errorf("could not read streams: %v", err)
	}
	if len(streams) != 2 {
		return result, fmt.Errorf("expected 2 streams, got %d", len(streams))
	}

	result.Salt = streams[0]
	result.Encrypted = streams[1]
	return result, err
}

// GetKey returns the settings key
func (t ESettings) GetKey(password string) []byte {
	settingsKey := decrypt.CreateLocalKey([]byte(password), t.Salt)
	return settingsKey
}

// Decrypt returns the decrypted settings
func (t ESettings) Decrypt(settingsKey []byte) ([]byte, error) {
	data, err := decrypt.DecryptLocal(t.Encrypted, settingsKey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt settings file: %v", err)
	}
	return data, nil
}

// Print streams description
func (t ESettings) Print() {
	fmt.Printf("salt\t%s\n", hex.EncodeToString(t.Salt))
	fmt.Printf("encrypted\t%s\n", hex.EncodeToString(t.Encrypted))
}
