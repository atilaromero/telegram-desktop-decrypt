package decrypted

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type DMap struct {
	Files map[string]uint32
}

func ReadDMap(data []byte) (DMap, error) {
	keyToFilename := func(key uint64) string {
		result := ""
		for _, c := range fmt.Sprintf("%016X", key) {
			result = string(c) + result
		}
		return result
	}
	result := DMap{
		Files: make(map[string]uint32),
	}
	r := bytes.NewReader(data[4:])
	var keytype uint32
	var key, first, second, p uint64
	var size uint32
	var count uint32
	for x := 0; ; x++ {
		err := binary.Read(r, binary.BigEndian, &keytype)
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return result, err
		}
		switch LSK[keytype].(type) {
		case SelfSerialized,
			Locations,
			ReportSpamStatuses,
			TrustedBots,
			RecentStickersOld,
			BackgroundOld,
			UserSettings,
			RecentHashtagsAndBots,
			StickersOld,
			FavedStickers,
			SavedGifsOld,
			SavedGifs,
			SavedPeers,
			ExportSettings:
			binary.Read(r, binary.BigEndian, &key)
			result.Files[keyToFilename(key)] = keytype
		case Background:
			for i := 0; i < 2; i++ {
				binary.Read(r, binary.BigEndian, &key)
				result.Files[keyToFilename(key)] = keytype
			}
		case StickersKeys:
			for i := 0; i < 4; i++ {
				binary.Read(r, binary.BigEndian, &key)
				result.Files[keyToFilename(key)] = keytype
			}
		case Draft,
			DraftPosition:
			binary.Read(r, binary.BigEndian, &count)
			for i := uint32(0); i < count; i++ {
				binary.Read(r, binary.BigEndian, &key)
				binary.Read(r, binary.BigEndian, &p)
				result.Files[keyToFilename(key)] = keytype
			}
		case Images,
			StickerImages,
			Audios:
			binary.Read(r, binary.BigEndian, &count)
			for i := uint32(0); i < count; i++ {
				binary.Read(r, binary.BigEndian, &key)
				binary.Read(r, binary.BigEndian, &first)
				binary.Read(r, binary.BigEndian, &second)
				binary.Read(r, binary.BigEndian, &size)
				result.Files[keyToFilename(key)] = keytype
			}
		default:
			return result, fmt.Errorf("keytype not treated: %d", keytype)
		}
	}
}
