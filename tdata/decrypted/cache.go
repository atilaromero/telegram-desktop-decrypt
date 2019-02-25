package decrypted

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lunixbochs/struc"
)

type locationStruct struct {
}

func ReadCache(data []byte, keytype uint32) (interface{}, error) {
	r := bytes.NewReader(data)
	switch LSK[keytype].(type) {
	case Audios:
		result := Audios{}
		err := struc.Unpack(r, &result)
		return result, err
	case StickerImages:
		result := StickerImages{}
		err := struc.Unpack(r, &result)
		return result, err
	case Images:
		result := Images{}
		err := struc.Unpack(r, &result)
		return result, err
	case Locations:
		locations := Locations{}
		location := Location{}
		err := binary.Read(r, binary.BigEndian, &locations.FullLen)
		if err != nil {
			return nil, err
		}
		for {
			err := struc.Unpack(r, &location)
			if err == io.EOF {
				break
			}
			if err != nil {
				return locations, err
			}
			locations.Locations = append(locations.Locations, location)
		}
		return locations, nil
	default:
		return nil, fmt.Errorf("stream type is not fully supported yet: %v", LSK[keytype])
	}
}
