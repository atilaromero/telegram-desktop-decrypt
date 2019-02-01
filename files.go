package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
)

func ReadStream(r io.Reader) ([]byte, error) {
	var streamSize uint32
	err := binary.Read(r, binary.BigEndian, &streamSize)
	if err != nil {
		return nil, err
	}
	result := make([]byte, streamSize)
	n, err := r.Read(result)
	return result[:n], err
}

// TdataFile is the generic structure of a tdata file.
type TdataFile struct {
	Version    uint32
	PartialMD5 [16]byte
	CorrectMD5 bool
	Data       []byte
}

// ReadTdataFile interprets the generic structure of a tdata file,
// reading the TDF$ magic bytes, version, and checking the 16bytes partial MD5 at the end.
func ReadTdataFile(f io.Reader) (TdataFile, error) {
	result := TdataFile{}
	var magic [4]byte
	_, err := f.Read(magic[:])
	if err != nil {
		return result, fmt.Errorf("could not read magic: %v", err)
	}
	if string(magic[:]) != "TDF$" {
		return result, fmt.Errorf("wrong magic")
	}
	err = binary.Read(f, binary.LittleEndian, &result.Version)
	if err != nil {
		return result, fmt.Errorf("could not read version: %v", err)
	}
	readAll, err := ioutil.ReadAll(f)
	if err != nil {
		return result, fmt.Errorf("could not read all file: %v", err)
	}
	dataSize := len(readAll) - 16
	result.Data = make([]byte, dataSize)
	copy(result.Data, readAll[:dataSize])
	copy(result.PartialMD5[:], readAll[dataSize:])
	calcMD5 := md5.New()
	calcMD5.Write(readAll[:dataSize])
	binary.Write(calcMD5, binary.LittleEndian, int32(dataSize))
	binary.Write(calcMD5, binary.LittleEndian, result.Version)
	calcMD5.Write(magic[:])
	gotMD5 := calcMD5.Sum([]byte{})
	result.CorrectMD5 = (string(result.PartialMD5[:]) == string(gotMD5[:16]))
	if !result.CorrectMD5 {
		err = fmt.Errorf("MD5 does not match. Expected %s, got %s",
			hex.EncodeToString(result.PartialMD5[:]),
			hex.EncodeToString(gotMD5[:16]))
	}
	return result, err
}

func (stat TdataFile) Print(verbose bool) {
	fmt.Printf("version\t%d\n", stat.Version)
	fmt.Printf("partialMD5\t%s\n", hex.EncodeToString(stat.PartialMD5[:]))
	fmt.Printf("correctMD5\t%t\n", stat.CorrectMD5)
	fmt.Printf("dataLength\t%d\n", len(stat.Data))
	var i int
	r := bytes.NewReader(stat.Data)
	for buf, err := ReadStream(r); err != io.EOF; buf, err = ReadStream(r) {
		if err != nil {
			log.Fatalf("error reading stream: %v", err)
		}
		if verbose {
			fmt.Printf("stream %3d\t%s\n", i, hex.EncodeToString(buf))
		} else {
			fmt.Printf("stream %3d\t%d\n", i, len(buf))
		}
		i++
	}
}

// TdataSettings reflects the streams contained in the tdata/settings0 file.
type TdataSettings struct {
	Salt      []byte
	Encrypted []byte
}

// ReadTdataSettings opens the tdata/settings0 or tdata/settings1
func ReadTdataSettings(f io.Reader) (TdataSettings, error) {
	result := TdataSettings{}
	tfile, err := ReadTdataFile(f)
	if err != nil {
		return result, fmt.Errorf("could not interpret file, error: %v", err)
	}
	mydata := bytes.NewReader(tfile.Data)
	result.Salt, err = ReadStream(mydata)
	if err != nil {
		return result, fmt.Errorf("could not read salt: %v", err)
	}
	result.Encrypted, err = ReadStream(mydata)
	if err != nil {
		return result, fmt.Errorf("could not read settingsEncrypted: %v", err)
	}
	return result, err
	// fmt.Printf("settingsKey (%d):\n", len(settingsKey))
	// fmt.Println(hex.EncodeToString(settingsKey[:]))
}
func (settings TdataSettings) GetKey(password string) []byte {
	settingsKey := CreateLocalKey([]byte(password), settings.Salt)
	return settingsKey
}
func (settings TdataSettings) Decrypt(settingsKey []byte) ([]byte, error) {
	decrypted, err := DecryptLocal(settings.Encrypted, settingsKey)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt settings file: %v", err)
	}
	return decrypted, nil
}

func (settings TdataSettings) Print() {
	fmt.Printf("salt\t%s\n", hex.EncodeToString(settings.Salt))
	fmt.Printf("encrypted\t%s\n", hex.EncodeToString(settings.Encrypted))
}

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
	passkey := CreateLocalKey([]byte(password), tdatamap.Salt)
	localkey, err := DecryptLocal(tdatamap.KeyEncrypted, passkey)
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
	decrypted, err := DecryptLocal(tdatamap.MapEncrypted, localkey)
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

func (tdatamap TdataMap) BulkDecrypt(localkey []byte, srcdir string, outdir string, verbose bool) error {
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
	for _, fpath := range files {
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
		encryptedfile := path.Join(srcdir, fpath.Name())
		decryptedfile := path.Join(keytypepath, fpath.Name())
		if verbose {
			fmt.Println(decryptedfile)
		}
		func(encryptedfile string, decryptedfile string, keytype uint32) {
			f, err := os.Open(encryptedfile)
			if err != nil {
				log.Fatalf("could not open file '%s': %v", encryptedfile, err)
			}
			defer f.Close()
			tdata, err := ReadTdataFile(f)
			if err != nil {
				log.Fatalf("error reading tdata file: %v", err)
			}
			r := bytes.NewReader(tdata.Data)
			streamdata, err := ReadStream(r)
			if err != nil {
				log.Fatalf("could not read stream: %v", err)
			}
			f.Close()
			decrypted, err := DecryptLocal(streamdata, localkey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not decrypt file (%s): %v\n", encryptedfile, err)
			}
			start := 0
			end := len(decrypted)
			switch lsk[keytype] {
			case "Images":
				start = 28
				end = end - 12
			}
			ioutil.WriteFile(decryptedfile, decrypted[start:end], 0644)
		}(encryptedfile, decryptedfile, keytype)
	}
	return nil
}
