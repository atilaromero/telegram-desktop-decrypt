package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
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
	fmt.Printf("salt size: %d\n", len(salt))
	fmt.Printf("settingsEncrypted size: %d\n", len(settingsEncrypted))
	settingsKey := CreateLocalKey([]byte{}, salt)
	fmt.Println(hex.EncodeToString(salt[:]))
	fmt.Println(hex.EncodeToString(settingsKey[:]))
}

func ReadStream(r io.Reader) []byte {
	var streamSize uint32
	err := binary.Read(r, binary.BigEndian, &streamSize)
	if err != nil {
		log.Fatal(err)
	}
	result := make([]byte, streamSize)
	r.Read(result)
	return result
}

func CreateLocalKey(pass []byte, salt []byte) []byte {
	iter := 4
	if len(pass) > 0 {
		iter = 4000
	}
	keyLen := 256
	result := pbkdf2.Key(pass, salt, iter, keyLen, sha1.New)
	return result
}

func PrepareAESOldmtp(globalKey []byte, msgKey []byte) (key []byte, iv []byte) {
	dataA := []byte{}
	dataA = append(dataA, msgKey...)
	dataA = append(dataA, globalKey[8:][:32]...)

	dataB := []byte{}
	dataB = append(dataB, globalKey[(8 + 32):][:16]...)
	dataB = append(dataB, msgKey...)
	dataB = append(dataB, globalKey[(8 + 32 + 16):][:16]...)

	dataC := []byte{}
	dataC = append(dataC, globalKey[(8 + 32 + 16 + 16):][:32]...)
	dataC = append(dataC, msgKey...)

	dataD := []byte{}
	dataD = append(dataD, msgKey...)
	dataD = append(dataD, globalKey[(8 + 32 + 16 + 16 + 32):][:32]...)

	sha1A := sha1.Sum(dataA)
	sha1B := sha1.Sum(dataB)
	sha1C := sha1.Sum(dataC)
	sha1D := sha1.Sum(dataD)

	key = []byte{}
	key = append(key, sha1A[:8]...)
	key = append(key, sha1B[8:20]...)
	key = append(key, sha1C[4:16]...)

	iv = []byte{}
	iv = append(iv, sha1A[8:20]...)
	iv = append(iv, sha1B[:8]...)
	iv = append(iv, sha1C[16:20]...)
	iv = append(iv, sha1D[:8]...)
	return key, iv
}

// func DecryptLocal(encrypted []byte, key []byte) []byte {
// 	cph, err := aes.NewCipher(key)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// cph.Decrypt(dst, src)
// 	return nil
// }
