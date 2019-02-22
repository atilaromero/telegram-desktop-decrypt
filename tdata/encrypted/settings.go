package encrypted

import (
	"encoding/hex"
	"fmt"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
	"github.com/atilaromero/telegram-desktop-decrypt/qt"
	"github.com/atilaromero/telegram-desktop-decrypt/tdata"
)

// Settings reflects the streams contained in the tdata/settings0 file.
type Settings struct {
	Salt      []byte
	Encrypted []byte
}

// ToSettings opens the tdata/settings0 or tdata/settings1
func ToSettings(tfile tdata.Physical) (Settings, error) {
	result := Settings{}
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
func (t Settings) GetKey(password string) []byte {
	settingsKey := decrypt.CreateLocalKey([]byte(password), t.Salt)
	return settingsKey
}

// Decrypt returns the decrypted settings
func (t Settings) Decrypt(settingsKey []byte) ([]byte, error) {
	decrypted, err := decrypt.DecryptLocal(t.Encrypted, settingsKey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt settings file: %v", err)
	}
	return decrypted, nil
}

// Print streams description
func (t Settings) Print() {
	fmt.Printf("salt\t%s\n", hex.EncodeToString(t.Salt))
	fmt.Printf("encrypted\t%s\n", hex.EncodeToString(t.Encrypted))
}
