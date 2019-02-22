package decrypted

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
	"github.com/atilaromero/telegram-desktop-decrypt/qt"
	"github.com/atilaromero/telegram-desktop-decrypt/tdata"
)

type FirstSecond struct {
	First    uint64
	Second   uint64
	Size     uint32
	Filename string
}

type locationStruct struct {
	First      uint64
	Second     uint64
	Legacytype uint32
	Len        int32
	Filename   []byte
	Bookmark   [5]byte
	Date       uint64
	Time       uint32
	Size       uint32
}

func SaveDecrypted(localkey []byte, td tdata.Physical, keytype uint32) (output []byte, firstSeconds []FirstSecond, err error) {
	firstSeconds = []FirstSecond{}
	streams, err := qt.ReadStreams(td.Data)
	if err != nil {
		log.Fatalf("could not read stream: %v", err)
	}
	decrypted, err := decrypt.DecryptLocal(streams[0], localkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt file: %v\n", err)
		return nil, firstSeconds, err
	}
	r := bytes.NewReader(decrypted)
	switch LSK[keytype] {
	case "Audios",
		"StickerImages":
		return nil, nil, nil
	case "Images":
		return nil, nil, nil
	case "Locations":
		fullLen := uint32(0)
		err = binary.Read(r, binary.BigEndian, &fullLen)
		if err != nil {
			return nil, firstSeconds, err
		}
		location := locationStruct{}
		for {
			err = binary.Read(r, binary.BigEndian, &location.First)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, firstSeconds, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Second)
			if err != nil {
				return nil, firstSeconds, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Legacytype)
			if err != nil {
				return nil, firstSeconds, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Len)
			if err != nil {
				return nil, firstSeconds, err
			}
			if location.Len == -1 {
				break
			}
			location.Filename = make([]byte, location.Len)
			n, err := r.Read(location.Filename)
			if err != nil {
				return nil, firstSeconds, err
			}
			_, err = r.Read(location.Bookmark[:])
			if err != nil {
				return nil, firstSeconds, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Date)
			if err != nil {
				return nil, firstSeconds, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Time)
			if err != nil {
				return nil, firstSeconds, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Size)
			if err != nil {
				return nil, firstSeconds, err
			}
			firstSeconds = append(firstSeconds, FirstSecond{
				First:    location.First,
				Second:   location.Second,
				Filename: qt.ConvertUtf16(location.Filename[:n]),
				Size:     location.Size,
			})
		}
		return nil, firstSeconds, err
	default:
		fmt.Fprintf(os.Stderr, "%s stream type is not fully supported yet: it was decrypted but not parsed\n", LSK[keytype])
		return decrypted, firstSeconds, err
	}
	return decrypted, firstSeconds, err
}
