package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	var f *os.File
	var err error
	if len(os.Args) > 1 {
		f, err = os.Open(os.Args[1])
		if err != nil {
			panic(err)
		}
	} else {
		f = os.Stdin
	}
	b := make([]byte, 700000)
	n, err := f.Read(b)
	if err != nil {
		panic(err)
	}
	s := hex.EncodeToString(b[:n])
	fmt.Println(s)
}
