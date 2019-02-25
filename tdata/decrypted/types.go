package decrypted

import "fmt"

var LSK = map[uint32]interface{}{
	0x00: UserMap{},
	0x01: Draft{},
	0x02: DraftPosition{},
	0x03: Images{},
	0x04: Locations{},
	0x05: StickerImages{},
	0x06: Audios{},
	0x07: RecentStickersOld{},
	0x08: BackgroundOld{},
	0x09: UserSettings{},
	0x0a: RecentHashtagsAndBots{},
	0x0b: StickersOld{},
	0x0c: SavedPeers{},
	0x0d: ReportSpamStatuses{},
	0x0e: SavedGifsOld{},
	0x0f: SavedGifs{},
	0x10: StickersKeys{},
	0x11: TrustedBots{},
	0x12: FavedStickers{},
	0x13: ExportSettings{},
	0x14: Background{},
	0x15: SelfSerialized{},
}

func ReverseLSK(a interface{}) uint32 {
	switch a.(type) {
	case UserMap:
		return 0x00
	case Draft:
		return 0x01
	case DraftPosition:
		return 0x02
	case Images:
		return 0x03
	case Locations:
		return 0x04
	case StickerImages:
		return 0x05
	case Audios:
		return 0x06
	case RecentStickersOld:
		return 0x07
	case BackgroundOld:
		return 0x08
	case UserSettings:
		return 0x09
	case RecentHashtagsAndBots:
		return 0x0a
	case StickersOld:
		return 0x0b
	case SavedPeers:
		return 0x0c
	case ReportSpamStatuses:
		return 0x0d
	case SavedGifsOld:
		return 0x0e
	case SavedGifs:
		return 0x0f
	case StickersKeys:
		return 0x10
	case TrustedBots:
		return 0x11
	case FavedStickers:
		return 0x12
	case ExportSettings:
		return 0x13
	case Background:
		return 0x14
	case SelfSerialized:
		return 0x15
	default:
		panic(fmt.Errorf("could not use ReverseLSK on %v", a))
	}
}

type Images struct {
	FullLen    uint32
	First      uint64
	Second     uint64
	LegacyType uint32
	Len        uint32 `struc:"sizeof=Data"`
	Data       []byte
}

type UserMap struct {
	Data []byte
}
type Draft struct {
	Data []byte
}
type DraftPosition struct {
	Data []byte
}
type Locations struct {
	FullLen   uint32
	Locations []Location
}
type Location struct {
	First      uint64
	Second     uint64
	LegacyType uint32
	Len        int32 `struc:"sizeof=Filename"`
	Filename   []byte
	Bookmark   [5]byte
	Date       uint64
	Time       uint32
	Size       uint32
}

type StickerImages struct {
	FullLen uint32
	First   uint64
	Second  uint64
	Len     uint32 `struc:"sizeof=Data"`
	Data    []byte
}
type Audios struct {
	FullLen uint32
	First   uint64
	Second  uint64
	Len     uint32 `struc:"sizeof=Data"`
	Data    []byte
}

type RecentStickersOld struct {
	Data []byte
}
type BackgroundOld struct {
	Data []byte
}
type UserSettings struct {
	Data []byte
}
type RecentHashtagsAndBots struct {
	Data []byte
}
type StickersOld struct {
	Data []byte
}
type SavedPeers struct {
	Data []byte
}
type ReportSpamStatuses struct {
	Data []byte
}
type SavedGifsOld struct {
	Data []byte
}
type SavedGifs struct {
	Data []byte
}
type StickersKeys struct {
	Data []byte
}
type TrustedBots struct {
	Data []byte
}
type FavedStickers struct {
	Data []byte
}
type ExportSettings struct {
	Data []byte
}
type Background struct {
	Data []byte
}
type SelfSerialized struct {
	Data []byte
}
