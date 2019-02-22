package encrypted

import (
	"fmt"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
	"github.com/atilaromero/telegram-desktop-decrypt/qt"
	"github.com/atilaromero/telegram-desktop-decrypt/tdata"
)

type Cache struct {
	Encrypted []byte
}

func ToCache(td tdata.Physical) (Cache, error) {
	result := Cache{}
	streams, err := qt.ReadStreams(td.Data)
	if err != nil {
		return result, fmt.Errorf("could not get mapped: %v", err)
	}
	if len(streams) != 1 {
		return result, fmt.Errorf("can only call ToMapped on files with a single stream")
	}
	result.Encrypted = streams[0]
	return result, err
}

func (tcache Cache) Decrypt(localkey []byte) ([]byte, error) {
	decrypted, err := decrypt.DecryptLocal(tcache.Encrypted, localkey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt cache file: %v", err)
	}
	return decrypted, nil
}
