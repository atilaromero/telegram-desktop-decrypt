package decrypted

import (
	"bytes"
	"encoding/binary"
)

type AudioHeader struct {
	Fulllen uint32
	First   uint64
	Second  uint64
	Len     uint32
}

type Audio struct {
	*AudioHeader
	Data []byte
}

func ParseAudio(b []byte) (Audio, error) {
	result := Audio{}
	r := bytes.NewReader(b)
	err := binary.Read(r, binary.BigEndian, &result.AudioHeader)
	if err != nil {
		return result, err
	}
	content := make([]byte, result.AudioHeader.Len)
	n, err := r.Read(content)
	if err != nil {
		return result, err
	}
	result.Data = content[:n]
	return result, nil
}
