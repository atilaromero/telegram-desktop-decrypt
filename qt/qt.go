package qt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
	"unicode/utf16"
)

// ReadStreams reads all Qt streams from input
// It uses []byte instead of io.Reader because
// all decrypted data already are []byte
func ReadStreams(b []byte) ([][]byte, error) {
	result := [][]byte{}
	r := bytes.NewReader(b)
	for buf, err := ReadStream(r); err != io.EOF; buf, err = ReadStream(r) {
		if err != nil {
			return nil, fmt.Errorf("error reading stream: %v", err)
		}
		result = append(result, buf)
	}
	return result, nil
}

// ReadStream reads a single Qt stream
func ReadStream(r io.Reader) ([]byte, error) {
	var streamSize uint32
	err := binary.Read(r, binary.BigEndian, &streamSize)
	if err != nil {
		return nil, err
	}
	result := make([]byte, streamSize)
	n, err := r.Read(result)
	return result[:n], err
}

func ConvertUtf16(b []byte) string {
	result := make([]uint16, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		result[i/2] = binary.BigEndian.Uint16(b[i : i+2])
	}
	return string(utf16.Decode(result))
}

var epoch = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

func QDateTime(qDate uint64, qTime uint32) time.Time {
	return epoch.Add(time.Hour * time.Duration(24*(qDate-2440588))).Add(time.Millisecond * time.Duration(qTime))
}
