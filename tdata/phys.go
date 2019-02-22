package tdata

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/atilaromero/telegram-desktop-decrypt/qt"
)

// Physical is the generic structure of a tdata file.
type Physical struct {
	Version    uint32
	PartialMD5 [16]byte
	CorrectMD5 bool
	Data       []byte
}

// ReadPhysical interprets the generic structure of a tdata file,
// reading the TDF$ magic bytes, version, and checking the 16bytes partial MD5 at the end.
func ReadPhysical(f io.Reader) (Physical, error) {
	result := Physical{}
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

// Print general information about this encrypted file
func (td Physical) Print(verbose bool) {
	fmt.Printf("version\t%d\n", td.Version)
	fmt.Printf("partialMD5\t%s\n", hex.EncodeToString(td.PartialMD5[:]))
	fmt.Printf("correctMD5\t%t\n", td.CorrectMD5)
	fmt.Printf("dataLength\t%d\n", len(td.Data))
	var i int
	bufs, err := qt.ReadStreams(td.Data)
	if err != nil {
		log.Fatalf("error reading stream: %v", err)
	}
	for _, buf := range bufs {
		if verbose {
			fmt.Printf("stream %3d\t%s\n", i, hex.EncodeToString(buf))
		} else {
			fmt.Printf("stream %3d\t%d\n", i, len(buf))
		}
		i++
	}
}
