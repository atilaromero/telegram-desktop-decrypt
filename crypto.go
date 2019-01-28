package main

import (
	"crypto/aes"
	"crypto/sha1"
	"fmt"
	"log"

	"golang.org/x/crypto/pbkdf2"

	"github.com/karlmcguire/ige"
)

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

func DecryptLocal(encryptedMsg []byte, globalKey []byte) ([]byte, error) {
	msgKey := encryptedMsg[:16]
	encrypted := encryptedMsg[16:]
	out := make([]byte, len(encrypted))
	key, iv := PrepareAESOldmtp(globalKey, msgKey)
	cph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	i := ige.NewIGEDecrypter(cph, iv)
	i.CryptBlocks(out, encrypted)
	partialSha1 := sha1.Sum(out)
	if string(msgKey) != string(partialSha1[:16]) {
		return out, fmt.Errorf("wrong key")
	}
	return out, nil
}
