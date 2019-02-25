package decrypted

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"

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
		result := Locations{}
		location := Location{}
		err := binary.Read(r, binary.BigEndian, &result.FullLen)
		if err != nil {
			return nil, err
		}
		for {
			err := struc.Unpack(r, &location)
			if err == io.EOF {
				break
			}
			if err != nil {
				return result, err
			}
			result.Locations = append(result.Locations, location)
		}
		return result, nil
	case ReportSpamStatuses:
		result := ReportSpamStatuses{}
		err := struc.Unpack(r, &result)
		return result, err
	case UserSettings:
		result := UserSettings{}
		err := struc.Unpack(r, &result.FullLen)
		if err != nil {
			return nil, err
		}
		var blockID uint32
		for {
			err := struc.Unpack(r, &blockID)
			if err == io.EOF {
				break
			}
			if err != nil {
				return result, err
			}
			readUserSetting(&result, blockID)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("stream type is not fully supported yet: %v", LSK[keytype])
	}
}

func readUserSetting(result *UserSettings, blockID uint32) error {
	fieldName := DBI[blockID]
	field := reflect.Indirect(reflect.ValueOf(result)).FieldByName(fieldName)
	switch fieldName {
	case "":
		return nil
	}
	fmt.Println(field)
	return nil
}
