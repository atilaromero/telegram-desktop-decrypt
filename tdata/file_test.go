package tdata

import (
	"bytes"
	"encoding/hex"
	"log"
)

func ExampleTdataFile() {
	settings0, _ := hex.DecodeString(hexSettings0)
	tdatafile, err := ReadTdataFile(bytes.NewReader(settings0))
	if err != nil {
		log.Fatal(err)
	}
	tdatafile.Print(false)
	// Output:
	// version	1005002
	// partialMD5	afcfca85676e873236b98f34c842e76a
	// correctMD5	true
	// dataLength	1000
	// stream   0	32
	// stream   1	960
}
