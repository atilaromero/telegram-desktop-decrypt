package tdata

import "fmt"

func ExampleConvertUtf16() {
	b := []byte{0x00, 0x43, 0x00, 0x3a}
	fmt.Printf("%v", ConvertUtf16(b))
	// Output:
	// C:
}

// func Example() {
// 	f, err := os.Open("/home/atila.alr/.local/share/TelegramDesktop/tdata/D877F783D5D3EF8C/map0")
// 	if err != nil {
// 		panic(err)
// 	}
// 	b := make([]byte, 5000)
// 	n, err := f.Read(b)
// 	if err != nil {
// 		panic(err)
// 	}
// 	s := hex.EncodeToString(b[:n])
// 	fmt.Println(s)
// 	// Output:
// 	//
// }
