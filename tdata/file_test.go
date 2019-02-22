package tdata

import (
	"bytes"
	"encoding/hex"
	"log"
)

func ExampleFile_Print() {
	settings0, _ := hex.DecodeString(hexSettings0) // hexSettings0 is at settings_test.go
	tdatafile, err := ReadFile(bytes.NewReader(settings0))
	if err != nil {
		log.Fatal(err)
	}
	tdatafile.Print(false)
	// Output:
	// version	1003007
	// partialMD5	994db24bee29cf88f5dad74699db7c98
	// correctMD5	true
	// dataLength	888
	// stream   0	32
	// stream   1	848
}
