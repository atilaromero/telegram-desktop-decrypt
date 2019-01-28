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
		return nil, fmt.Errorf("error reading stream: %v", err)
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

// PrintTdataFile reads a tdata file and prints some data.
func PrintTdataFile(f io.Reader, verbose bool) {
	stat, err := ReadTdataFile(f)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("version\t%d\n", stat.Version)
	fmt.Printf("partialMD5\t%s\n", hex.EncodeToString(stat.PartialMD5[:]))
	fmt.Printf("correctMD5\t%t\n", stat.CorrectMD5)
	fmt.Printf("dataLength\t%d\n", len(stat.Data))
	var i int
	var buf []byte
	for pos := 0; pos < len(stat.Data); pos += len(buf) {
		buf, err = ReadStream(bytes.NewReader(stat.Data[pos:]))
		if err == io.EOF {
			break
		}
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

func getSettingsKey(settings TdataSettings, optional_password ...string) ([]byte, error) {
	pass := []byte{}
	if len(optional_password) > 0 {
		pass = []byte(optional_password[0])
	}
	return CreateLocalKey(pass, settings.Salt), nil
}

func decryptSettings(settings TdataSettings, settingsKey []byte) ([]byte, error) {
	return DecryptLocal(settings.Encrypted, settingsKey)
}

func PrintTdataSettings(r io.Reader) {
	settings, err := ReadTdataSettings(r)
	if err != nil {
		log.Fatalf("could not print settings, error: %v", err)
	}
	fmt.Printf("salt\t%s\n", hex.EncodeToString(settings.Salt))
	fmt.Printf("encrypted\t%s\n", hex.EncodeToString(settings.Encrypted))
}
