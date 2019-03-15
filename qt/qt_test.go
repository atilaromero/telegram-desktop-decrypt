package qt

import (
	"fmt"
)

func ExampleConvertUtf16() {
	b := []byte{0x00, 0x43, 0x00, 0x3a}
	fmt.Printf("%v", ConvertUtf16(b))
	// Output:
	// C:
}

func ExampleQDateTime() {
	d := uint64(0x000000000025805f)
	t := uint32(0x049649db)
	fmt.Println(QDateTime(d, t))
	// Output:
	// 2016-11-02 21:22:38.171 +0000 UTC
}
