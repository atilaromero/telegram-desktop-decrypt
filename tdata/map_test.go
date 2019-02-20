package tdata

import (
	"fmt"
)

func ExampleConvertUtf16() {
	b := []byte{0x00, 0x43, 0x00, 0x3a}
	fmt.Printf("%v", ConvertUtf16(b))
	// Output:
	// C:
}
