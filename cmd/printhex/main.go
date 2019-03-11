package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	f, err := os.Open(os.Args[1])

	if err != nil {
		panic(err)
	}
	b := make([]byte, 700000)
	n, err := f.Read(b)
	if err != nil {
		panic(err)
	}
	s := hex.EncodeToString(b[:n])
	fmt.Println(s)
}
