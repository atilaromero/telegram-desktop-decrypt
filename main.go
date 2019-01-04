package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	filename := os.Args[1]
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("could not open file '%s': %v", filename, err)
	}
	defer f.Close()
	readAll, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(readAll))
	PrintTdataFile(f)
}
