package encrypted

import (
	"fmt"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
	"github.com/atilaromero/telegram-desktop-decrypt/qt"

	"github.com/atilaromero/telegram-desktop-decrypt/tdata"
)

// TMap reflects the streams contained in the tdata/D877F783D5D3EF8C/map0 file.
type TMap struct {
	Salt         []byte
	KeyEncrypted []byte
	MapEncrypted []byte
}

// ToTMap opens the map file
func ToTMap(tfile tdata.Physical) (TMap, error) {
	result := TMap{}
	streams, err := qt.ReadStreams(tfile.Data)
	if err != nil {
		return result, fmt.Errorf("could not read map streams: %v", err)
	}
	if len(streams) != 3 {
		return result, fmt.Errorf("expected 3 streams, got %d", len(streams))
	}
	result.Salt = streams[0]
	result.KeyEncrypted = streams[1]
	result.MapEncrypted = streams[2]
	return result, err
}

// GetKey extracts the global key from a map file.
// That key will be used later to decrypt other files.
func (tmap TMap) GetKey(password string) ([]byte, error) {
	passkey := decrypt.CreateLocalKey([]byte(password), tmap.Salt)
	localkey, err := decrypt.DecryptLocal(tmap.KeyEncrypted, passkey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt map key: %v", err)
	}
	streams, err := qt.ReadStreams(localkey)
	if err != nil {
		return nil, fmt.Errorf("could not read streams: %v", err)
	}
	if len(streams) != 1 {
		return nil, fmt.Errorf("expecting 1 stream, got %d", len(streams))
	}
	return streams[0], nil
}

func (tmap TMap) Decrypt(localkey []byte) ([]byte, error) {
	decrypted, err := decrypt.DecryptLocal(tmap.MapEncrypted, localkey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt map file: %v", err)
	}
	return decrypted, nil
}
