package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	f, err := os.Open("settings0")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	// fstat, err := f.Stat()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fsize := fstat.Size()
	var magic [4]byte
	_, err = f.Read(magic[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("magic: %s\n", string(magic[:]))
	var version uint32
	err = binary.Read(f, binary.LittleEndian, &version)
	fmt.Printf("version: %d\n", version)
	salt := ReadStream(f)
	settingsEncrypted := ReadStream(f)
	fmt.Printf("salt (%d):\n", len(salt))
	fmt.Println(hex.EncodeToString(salt[:]))
	fmt.Printf("settingsEncrypted (%d):\n", len(settingsEncrypted))
	fmt.Println(hex.EncodeToString(settingsEncrypted[:]))
	settingsKey := CreateLocalKey([]byte{}, salt)
	fmt.Printf("settingsKey (%d):\n", len(settingsKey))
	fmt.Println(hex.EncodeToString(settingsKey[:]))
}
