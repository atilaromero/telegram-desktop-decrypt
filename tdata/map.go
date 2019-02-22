package tdata

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
)

// TMap reflects the streams contained in the tdata/D877F783D5D3EF8C/map0 file.
type TMap struct {
	Salt         []byte
	KeyEncrypted []byte
	MapEncrypted []byte
}

// ReadTMap opens the map file
func ReadTMap(f io.Reader) (TMap, error) {
	result := TMap{}
	tfile, err := ReadFile(f)
	if err != nil {
		return result, fmt.Errorf("could not interpret file, error: %v", err)
	}
	streams, err := ReadQtStreams(tfile.Data)
	if err != nil {
		return result, fmt.Errorf("could not read map streams: %v", err)
	}
	result.Salt = streams[0]
	result.KeyEncrypted = streams[1]
	result.MapEncrypted = streams[2]
	return result, err
}

// GetKey extracts the global key from a map file.
// That key will be used later to decrypt other files.
func (tdatamap TMap) GetKey(password string) ([]byte, error) {
	passkey := decrypt.CreateLocalKey([]byte(password), tdatamap.Salt)
	decrypted, err := tdatamap.Decrypt(passkey)
	if err != nil {
		return nil, err
	}
	streams, err := ReadQtStreams(decrypted)
	if err != nil {
		return nil, fmt.Errorf("could not read streams: %v", err)
	}
	localkey := streams[0]
	return localkey, nil
}

func (tdatamap TMap) Decrypt(localkey []byte) ([]byte, error) {
	decrypted, err := decrypt.DecryptLocal(tdatamap.MapEncrypted, localkey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt map file: %v", err)
	}
	return decrypted, nil
}

var LSK = map[uint32]string{
	0x00: "UserMap",
	0x01: "Draft",
	0x02: "DraftPosition",
	0x03: "Images",
	0x04: "Locations",
	0x05: "StickerImages",
	0x06: "Audios",
	0x07: "RecentStickersOld",
	0x08: "BackgroundOld",
	0x09: "UserSettings",
	0x0a: "RecentHashtagsAndBots",
	0x0b: "StickersOld",
	0x0c: "SavedPeers",
	0x0d: "ReportSpamStatuses",
	0x0e: "SavedGifsOld",
	0x0f: "SavedGifs",
	0x10: "StickersKeys",
	0x11: "TrustedBots",
	0x12: "FavedStickers",
	0x13: "ExportSettings",
	0x14: "Background",
	0x15: "SelfSerialized",
}

func (tdatamap TMap) ListKeys(localkey []byte) (map[string]uint32, error) {
	result := make(map[string]uint32)
	decrypted, err := tdatamap.Decrypt(localkey)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(decrypted[4:])
	var keytype uint32
	var key, first, second, p uint64
	var size uint32
	var count uint32
	for x := 0; ; x++ {
		err = binary.Read(r, binary.BigEndian, &keytype)
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return result, err
		}
		switch LSK[keytype] {
		case "SelfSerialized",
			"Locations",
			"ReportSpamStatuses",
			"TrustedBots",
			"RecentStickersOld",
			"BackgroundOld",
			"UserSettings",
			"RecentHashtagsAndBots",
			"StickersOld",
			"FavedStickers",
			"SavedGifsOld",
			"SavedGifs",
			"SavedPeers",
			"ExportSettings":
			binary.Read(r, binary.BigEndian, &key)
			result[fmt.Sprintf("%016X", key)] = keytype
		case "Background":
			for i := 0; i < 2; i++ {
				binary.Read(r, binary.BigEndian, &key)
				result[fmt.Sprintf("%016X", key)] = keytype
			}
		case "StickersKeys":
			for i := 0; i < 4; i++ {
				binary.Read(r, binary.BigEndian, &key)
				result[fmt.Sprintf("%016X", key)] = keytype
			}
		case "Draft",
			"DraftPosition":

			binary.Read(r, binary.BigEndian, &count)
			for i := uint32(0); i < count; i++ {
				binary.Read(r, binary.BigEndian, &key)
				binary.Read(r, binary.BigEndian, &p)
				result[fmt.Sprintf("%016X", key)] = keytype
			}
		case "Images",
			"StickerImages",
			"Audios":

			binary.Read(r, binary.BigEndian, &count)
			for i := uint32(0); i < count; i++ {
				binary.Read(r, binary.BigEndian, &key)
				binary.Read(r, binary.BigEndian, &first)
				binary.Read(r, binary.BigEndian, &second)
				binary.Read(r, binary.BigEndian, &size)
				result[fmt.Sprintf("%016X", key)] = keytype
			}
		default:
			return result, fmt.Errorf("keytype not treated: %d", keytype)
		}
	}
}

type FirstSecond struct {
	First    uint64
	Second   uint64
	Size     uint32
	Filename string
}

type Mapped struct {
	KeyType uint32
	Data    []byte
}

func (td File) ToMapped(localkey []byte, keytype uint32) (Mapped, error) {
	mapped := Mapped{
		KeyType: keytype,
	}
	streams, err := ReadQtStreams(td.Data)
	if err != nil {
		return mapped, fmt.Errorf("could not get mapped: %v", err)
	}
	if len(streams) != 1 {
		return mapped, fmt.Errorf("can only call ToMapped on files with a single stream")
	}
	decrypted, err := decrypt.DecryptLocal(streams[0], localkey)
	if err != nil {
		return mapped, fmt.Errorf("could not decrypt file: %v\n", err)
	}
	mapped.Data = decrypted
	return mapped, err
}

func SaveDecrypted(localkey []byte, td File, keytype uint32) (output []byte, firstSeconds []FirstSecond, err error) {
	firstSeconds = []FirstSecond{}
	streams, err := ReadQtStreams(td.Data)
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
		header := audioStruct{}
		err := binary.Read(r, binary.BigEndian, &header)
		if err != nil {
			return nil, firstSeconds, err
		}
		data := make([]byte, header.Len)
		n, err := r.Read(data)
		if err != nil {
			return nil, firstSeconds, err
		}
		firstSeconds = append(firstSeconds, FirstSecond{
			First:  header.First,
			Second: header.Second,
			Size:   header.Len,
		})
		return data[:n], firstSeconds, nil
	case "Images":
		header := imageStruct{}
		err := binary.Read(r, binary.BigEndian, &header)
		if err != nil {
			return nil, firstSeconds, err
		}
		data := make([]byte, header.Len)
		n, err := r.Read(data)
		if err != nil {
			return nil, firstSeconds, err
		}
		firstSeconds = append(firstSeconds, FirstSecond{
			First:  header.First,
			Second: header.Second,
			Size:   header.Len,
		})
		return data[:n], firstSeconds, nil
	case "Locations":
		fullLen := uint32(0)
		err := binary.Read(r, binary.BigEndian, &fullLen)
		if err != nil {
			return nil, firstSeconds, err
		}
		location := locationStruct{}
		for {
			err := binary.Read(r, binary.BigEndian, &location.First)
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
				Filename: ConvertUtf16(location.Filename[:n]),
				Size:     location.Size,
			})
		}
		return nil, firstSeconds, err
	default:
		fmt.Fprintf(os.Stderr, "%s stream type is not fully supported yet: it was decrypted but not parsed\n", LSK[keytype])
		return decrypted, firstSeconds, err
	}
}

var epoch = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

func qDateTime(qDate uint64, qTime uint32) time.Time {
	return epoch.Add(time.Hour * time.Duration(24*(qDate-2440588))).Add(time.Millisecond * time.Duration(qTime))
}

type imageStruct struct {
	Fulllen    uint32
	First      uint64
	Second     uint64
	Legacytype uint32
	Len        uint32
}

type audioStruct struct {
	Fulllen uint32
	First   uint64
	Second  uint64
	Len     uint32
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
