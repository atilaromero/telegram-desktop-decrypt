package decrypted

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"

	"github.com/atilaromero/telegram-desktop-decrypt/qt"
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
		err := binary.Read(r, binary.BigEndian, &result.FullLen)
		if err != nil {
			return nil, err
		}
		for {
			location := Location{}
			err := struc.Unpack(r, &location)
			if err == io.ErrUnexpectedEOF || err == io.EOF {
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
			err = readUserSetting(r, &result, blockID)
			if err != nil {
				return result, err
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("stream type is not fully supported yet: %v", LSK[keytype])
	}
}

func readUserSetting(r *bytes.Reader, result *UserSettings, blockID uint32) error {
	fieldName, ok := DBI[blockID]
	if !ok {
		return fmt.Errorf("blockID not found: %v", blockID)
	}
	field := reflect.Indirect(reflect.ValueOf(result)).FieldByName(fieldName)
	err := readField(r, field)
	if err != nil {
		return fmt.Errorf("Error: %v: %v", fieldName, err)
	}
	return nil
}

func readField(r *bytes.Reader, field reflect.Value) error {
	switch field.Kind() {
	case reflect.Struct:
		for i := 0; i < field.NumField(); i++ {
			readField(r, field.Field(i))
		}
	case reflect.Slice:
		switch field.Type().Elem().Kind() {
		case reflect.Uint8:
			len := int32(0)
			struc.Unpack(r, &len)
			if len < 0 {
				field.SetBytes([]byte{})
				return nil
			}
			b := make([]byte, len)
			err := struc.Unpack(r, b)
			if err != nil {
				return err
			}
			field.SetBytes(b)
		default:
			len := int32(0)
			struc.Unpack(r, &len)
			slice := reflect.MakeSlice(field.Type(), int(len), int(len))
			for i := 0; i < int(len); i++ {
				readField(r, slice.Index(i))
			}
			field.Set(slice)
			return nil
		}
	case reflect.String:
		len := int32(0)
		struc.Unpack(r, &len)
		if len < 0 {
			field.SetString("")
			return nil
		}
		b := make([]byte, len)
		err := struc.Unpack(r, b)
		if err != nil {
			return err
		}
		field.SetString(qt.ConvertUtf16(b))
		return nil
	default:
		interf := field.Addr().Interface()
		return struc.Unpack(r, interf)
	}
	return nil
}
