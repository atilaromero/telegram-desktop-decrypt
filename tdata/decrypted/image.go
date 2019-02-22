package decrypted

type Image struct {
	Fulllen    uint32
	First      uint64
	Second     uint64
	Legacytype uint32
	Len        uint32 `struc:"sizeof=Data"`
	Data       []byte
}
