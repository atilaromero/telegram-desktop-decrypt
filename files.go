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

const (
	lskUserMap               = 0x00
	lskDraft                 = 0x01 // data: PeerId peer
	lskDraftPosition         = 0x02 // data: PeerId peer
	lskImages                = 0x03 // data: StorageKey location
	lskLocations             = 0x04 // no data
	lskStickerImages         = 0x05 // data: StorageKey location
	lskAudios                = 0x06 // data: StorageKey location
	lskRecentStickersOld     = 0x07 // no data
	lskBackgroundOld         = 0x08 // no data
	lskUserSettings          = 0x09 // no data
	lskRecentHashtagsAndBots = 0x0a // no data
	lskStickersOld           = 0x0b // no data
	lskSavedPeers            = 0x0c // no data
	lskReportSpamStatuses    = 0x0d // no data
	lskSavedGifsOld          = 0x0e // no data
	lskSavedGifs             = 0x0f // no data
	lskStickersKeys          = 0x10 // no data
	lskTrustedBots           = 0x11 // no data
	lskFavedStickers         = 0x12 // no data
	lskExportSettings        = 0x13 // no data
	lskBackground            = 0x14 // no data
	lskSelfSerialized        = 0x15 // serialized self
)

func (tdatamap TdataMap) Interpret(localkey []byte) ([]byte, error) {

	decrypted, err := tdatamap.Decrypt(localkey)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(decrypted[4:])
	var keytype uint32
	err = binary.Read(r, binary.BigEndian, &keytype)
	if err != nil {
		return nil, fmt.Errorf("could not read keytype: %v", err)
	}
	switch keytype {
	case 3:
		fmt.Println(keytype)
	default:
		fmt.Println("not treated", keytype)
	}

	return decrypted, nil
}
