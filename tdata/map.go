package tdata

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"
	"unicode/utf16"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
)

// TdataMap reflects the streams contained in the tdata/D877F783D5D3EF8C/map0 file.
type TdataMap struct {
	Salt         []byte
	KeyEncrypted []byte
	MapEncrypted []byte
}

// ReadTdataMap opens the map file
func ReadTdataMap(f io.Reader) (TdataMap, error) {
	result := TdataMap{}
	tfile, err := ReadTdataFile(f)
	if err != nil {
		return result, fmt.Errorf("could not interpret file, error: %v", err)
	}
	mydata := bytes.NewReader(tfile.Data)
	result.Salt, err = ReadStream(mydata)
	if err != nil {
		return result, fmt.Errorf("could not read salt: %v", err)
	}
	result.KeyEncrypted, err = ReadStream(mydata)
	if err != nil {
		return result, fmt.Errorf("could not read keyEncrypted: %v", err)
	}
	result.MapEncrypted, err = ReadStream(mydata)
	if err != nil {
		return result, fmt.Errorf("could not read mapEncrypted: %v", err)
	}
	return result, err
}

func (tdatamap TdataMap) GetKey(password string) ([]byte, error) {
	passkey := decrypt.CreateLocalKey([]byte(password), tdatamap.Salt)
	localkey, err := decrypt.DecryptLocal(tdatamap.KeyEncrypted, passkey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt map file: %v", err)
	}
	localkey, err = ReadStream(bytes.NewReader(localkey))
	if err != nil {
		return nil, fmt.Errorf("could not read localkey stream: %v", err)
	}
	return localkey, nil
}

func (tdatamap TdataMap) Decrypt(localkey []byte) ([]byte, error) {
	decrypted, err := decrypt.DecryptLocal(tdatamap.MapEncrypted, localkey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt map file: %v", err)
	}
	return decrypted, nil
}

var lsk = map[uint32]string{
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

func (tdatamap TdataMap) ListKeys(localkey []byte) (map[string]uint32, error) {
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
		switch lsk[keytype] {
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

func (tdatamap TdataMap) BulkDecrypt(localkey []byte, srcdir string, outdir string) error {
	listkeys, err := tdatamap.ListKeys(localkey)
	if err != nil {
		return err
	}
	files, err := ioutil.ReadDir(srcdir)
	if err != nil {
		return err
	}
	err = os.Mkdir(outdir, 0755)
	if err != nil {
		return fmt.Errorf("outdir should not exist: %v", err)
	}
	lf, err := os.Create(path.Join(outdir, "locations.csv"))
	if err != nil {
		return fmt.Errorf("could not create locations.csv: %v", err)
	}
	defer lf.Close()
	filesf, err := os.Create(path.Join(outdir, "files.csv"))
	if err != nil {
		return fmt.Errorf("could not create files.csv: %v", err)
	}
	defer filesf.Close()
	for _, fpath := range files {
		if fpath.Name() == "map0" || fpath.Name() == "map1" {
			continue
		}
		reversedkey := fpath.Name()[:len(fpath.Name())-1]
		key := ""
		for _, c := range reversedkey {
			key = string(c) + key
		}
		var typename string
		keytype, ok := listkeys[key]
		if ok {
			typename = lsk[keytype]
		} else {
			typename = "Unknown"
		}
		keytypepath := path.Join(outdir, typename)
		os.Mkdir(keytypepath, 0755) // ignore error
		if typename == "Images" {
			keytypepath = path.Join(keytypepath, fpath.Name()[:2])
			os.Mkdir(keytypepath, 0755) // ignore error
		}
		encryptedfile := path.Join(srcdir, fpath.Name())
		decryptedfile := path.Join(keytypepath, fpath.Name())
		newlocationIDs, newoutputIDs, err := saveDecrypted(localkey, encryptedfile, decryptedfile, keytype)
		if err != nil {
			return err
		}
		for _, l := range newlocationIDs {
			fmt.Fprintf(lf, "%16x\t%16x\t%d\t%s\n", l.First, l.Second, l.Size, l.Filename)
		}
		for _, l := range newoutputIDs {
			fmt.Fprintf(filesf, "%16x\t%16x\t%d\t%s\n", l.First, l.Second, l.Size, l.Filename)
		}
	}
	return nil
}

type FirstSecond struct {
	First    uint64
	Second   uint64
	Filename string
	Size     uint32
}

func saveDecrypted(localkey []byte, encryptedfile string, decryptedfile string, keytype uint32) (locationIDs, outputIDs []FirstSecond, err error) {
	locationIDs = []FirstSecond{}
	outputIDs = []FirstSecond{}

	f, err := os.Open(encryptedfile)
	if err != nil {
		log.Fatalf("could not open file '%s': %v", encryptedfile, err)
	}
	defer f.Close()
	td, err := ReadTdataFile(f)
	if err != nil {
		log.Fatalf("error reading tdata file: %v", err)
	}
	r := bytes.NewReader(td.Data)
	streamdata, err := ReadStream(r)
	if err != nil {
		log.Fatalf("could not read stream: %v", err)
	}
	f.Close()
	decrypted, err := decrypt.DecryptLocal(streamdata, localkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt file (%s): %v\n", encryptedfile, err)
		return locationIDs, outputIDs, err
	}
	r = bytes.NewReader(decrypted)
	switch lsk[keytype] {
	case "Audios",
		"StickerImages":
		header := audioStruct{}
		err := binary.Read(r, binary.BigEndian, &header)
		if err != nil {
			return locationIDs, outputIDs, err
		}
		data := make([]byte, header.Len)
		n, err := r.Read(data)
		if err != nil {
			return locationIDs, outputIDs, err
		}
		outputIDs = append(outputIDs, FirstSecond{
			Filename: decryptedfile,
			First:    header.First,
			Second:   header.Second,
			Size:     header.Len,
		})
		ioutil.WriteFile(decryptedfile, data[:n], 0644)
	case "Images":
		header := imageStruct{}
		err := binary.Read(r, binary.BigEndian, &header)
		if err != nil {
			return locationIDs, outputIDs, err
		}
		data := make([]byte, header.Len)
		n, err := r.Read(data)
		if err != nil {
			return locationIDs, outputIDs, err
		}
		outputIDs = append(outputIDs, FirstSecond{
			Filename: decryptedfile,
			First:    header.First,
			Second:   header.Second,
			Size:     header.Len,
		})
		ioutil.WriteFile(decryptedfile, data[:n], 0644)
	case "Locations":
		fullLen := uint32(0)
		err := binary.Read(r, binary.BigEndian, &fullLen)
		if err != nil {
			return locationIDs, outputIDs, err
		}
		location := locationStruct{}
		for {
			err := binary.Read(r, binary.BigEndian, &location.First)
			if err == io.EOF {
				break
			}
			if err != nil {
				return locationIDs, outputIDs, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Second)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Legacytype)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Len)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			if location.Len == -1 {
				break
			}
			location.Filename = make([]byte, location.Len)
			n, err := r.Read(location.Filename)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			_, err = r.Read(location.Bookmark[:])
			if err != nil {
				return locationIDs, outputIDs, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Date)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Time)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			err = binary.Read(r, binary.BigEndian, &location.Size)
			if err != nil {
				return locationIDs, outputIDs, err
			}
			locationIDs = append(locationIDs, FirstSecond{
				First:    location.First,
				Second:   location.Second,
				Filename: ConvertUtf16(location.Filename[:n]),
				Size:     location.Size,
			})
		}
	default:
		fmt.Fprintf(os.Stderr, "%s stream type is not fully supported yet: it was decrypted but not parsed\n", lsk[keytype])
		ioutil.WriteFile(decryptedfile, decrypted, 0644)
	}
	return locationIDs, outputIDs, nil
}

func ConvertUtf16(b []byte) string {
	result := make([]uint16, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		result[i/2] = binary.BigEndian.Uint16(b[i : i+2])
	}
	return string(utf16.Decode(result))
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
