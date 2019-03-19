package decrypted

import (

	// "encoding/json"
	"encoding/json"
	"fmt"

	// "github.com/atilaromero/telegram-desktop-decrypt/qt"
	"time"
)

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

var DBI = map[uint32]string{
	0x00: "DbiKey",
	0x01: "DbiUser",
	0x02: "DbiDcOptionOldOld",
	0x03: "DbiChatSizeMax",
	0x04: "DbiMutePeer",
	0x05: "DbiSendKeyOld",
	0x06: "DbiAutoStart",
	0x07: "DbiStartMinimized",
	0x08: "DbiSoundNotify",
	0x09: "DbiWorkMode",
	0x0a: "DbiSeenTrayTooltip",
	0x0b: "DbiDesktopNotify",
	0x0c: "DbiAutoUpdate",
	0x0d: "DbiLastUpdateCheck",
	0x0e: "DbiWindowPosition",
	0x0f: "DbiConnectionTypeOld",
	0x11: "DbiDefaultAttach",
	0x12: "DbiCatsAndDogs",
	0x13: "DbiReplaceEmoji",
	0x14: "DbiAskDownloadPath",
	0x15: "DbiDownloadPathOld",
	0x16: "DbiScaleOld",
	0x17: "DbiEmojiTabOld",
	0x18: "DbiRecentEmojiOldOld",
	0x19: "DbiLoggedPhoneNumber",
	0x1a: "DbiMutedPeers",
	0x1c: "DbiNotifyView",
	0x1d: "DbiSendToMenu",
	0x1e: "DbiCompressPastedImage",
	0x1f: "DbiLangOld",
	0x20: "DbiLangFileOld",
	0x21: "DbiTileBackgroundOld",
	0x22: "DbiAutoLock",
	0x23: "DbiDialogLastPath",
	0x24: "DbiRecentEmojiOld",
	0x25: "DbiEmojiVariantsOld",
	0x26: "DbiRecentStickers",
	0x27: "DbiDcOptionOld",
	0x28: "DbiTryIPv6",
	0x29: "DbiSongVolume",
	0x30: "DbiWindowsNotificationsOld",
	0x31: "DbiIncludeMutedOld",
	0x32: "DbiMegagroupSizeMax",
	0x33: "DbiDownloadPath",
	0x34: "DbiAutoDownload",
	0x35: "DbiSavedGifsLimit",
	0x36: "DbiShowingSavedGifsOld",
	0x37: "DbiAutoPlay",
	0x38: "DbiAdaptiveForWide",
	0x39: "DbiHiddenPinnedMessages",
	0x3a: "DbiRecentEmoji",
	0x3b: "DbiEmojiVariants",
	0x40: "DbiDialogsMode",
	0x41: "DbiModerateMode",
	0x42: "DbiVideoVolume",
	0x43: "DbiStickersRecentLimit",
	0x44: "DbiNativeNotifications",
	0x45: "DbiNotificationsCount",
	0x46: "DbiNotificationsCorner",
	0x47: "DbiThemeKeyOld",
	0x48: "DbiDialogsWidthRatioOld",
	0x49: "DbiUseExternalVideoPlayer",
	0x4a: "DbiDcOptions",
	0x4b: "DbiMtpAuthorization",
	0x4c: "DbiLastSeenWarningSeenOld",
	0x4d: "DbiAuthSessionSettings",
	0x4e: "DbiLangPackKey",
	0x4f: "DbiConnectionType",
	0x50: "DbiStickersFavedLimit",
	0x51: "DbiSuggestStickersByEmoji",
	0x52: "DbiSuggestEmoji",
	0x53: "DbiTxtDomainString",
	0x54: "DbiThemeKey",
	0x55: "DbiTileBackground",
	0x56: "DbiCacheSettings",
	0x57: "DbiAnimationsDisabled",
	0x58: "DbiScalePercent",
	0x59: "DbiPlaybackSpeed",
	0x5a: "DbiLanguagesKey",
	333:  "DbiEncryptedWithSalt",
	444:  "DbiEncrypted",
	666:  "DbiVersion",
}

const (
	DbiKey                     = 0x00
	DbiUser                    = 0x01
	DbiDcOptionOldOld          = 0x02
	DbiChatSizeMax             = 0x03
	DbiMutePeer                = 0x04
	DbiSendKeyOld              = 0x05
	DbiAutoStart               = 0x06
	DbiStartMinimized          = 0x07
	DbiSoundNotify             = 0x08
	DbiWorkMode                = 0x09
	DbiSeenTrayTooltip         = 0x0a
	DbiDesktopNotify           = 0x0b
	DbiAutoUpdate              = 0x0c
	DbiLastUpdateCheck         = 0x0d
	DbiWindowPosition          = 0x0e
	DbiConnectionTypeOld       = 0x0f
	DbiDefaultAttach           = 0x11
	DbiCatsAndDogs             = 0x12
	DbiReplaceEmoji            = 0x13
	DbiAskDownloadPath         = 0x14
	DbiDownloadPathOld         = 0x15
	DbiScaleOld                = 0x16
	DbiEmojiTabOld             = 0x17
	DbiRecentEmojiOldOld       = 0x18
	DbiLoggedPhoneNumber       = 0x19
	DbiMutedPeers              = 0x1a
	DbiNotifyView              = 0x1c
	DbiSendToMenu              = 0x1d
	DbiCompressPastedImage     = 0x1e
	DbiLangOld                 = 0x1f
	DbiLangFileOld             = 0x20
	DbiTileBackgroundOld       = 0x21
	DbiAutoLock                = 0x22
	DbiDialogLastPath          = 0x23
	DbiRecentEmojiOld          = 0x24
	DbiEmojiVariantsOld        = 0x25
	DbiRecentStickers          = 0x26
	DbiDcOptionOld             = 0x27
	DbiTryIPv6                 = 0x28
	DbiSongVolume              = 0x29
	DbiWindowsNotificationsOld = 0x30
	DbiIncludeMutedOld         = 0x31
	DbiMegagroupSizeMax        = 0x32
	DbiDownloadPath            = 0x33
	DbiAutoDownload            = 0x34
	DbiSavedGifsLimit          = 0x35
	DbiShowingSavedGifsOld     = 0x36
	DbiAutoPlay                = 0x37
	DbiAdaptiveForWide         = 0x38
	DbiHiddenPinnedMessages    = 0x39
	DbiRecentEmoji             = 0x3a
	DbiEmojiVariants           = 0x3b
	DbiDialogsMode             = 0x40
	DbiModerateMode            = 0x41
	DbiVideoVolume             = 0x42
	DbiStickersRecentLimit     = 0x43
	DbiNativeNotifications     = 0x44
	DbiNotificationsCount      = 0x45
	DbiNotificationsCorner     = 0x46
	DbiThemeKeyOld             = 0x47
	DbiDialogsWidthRatioOld    = 0x48
	DbiUseExternalVideoPlayer  = 0x49
	DbiDcOptions               = 0x4a
	DbiMtpAuthorization        = 0x4b
	DbiLastSeenWarningSeenOld  = 0x4c
	DbiAuthSessionSettings     = 0x4d
	DbiLangPackKey             = 0x4e
	DbiConnectionType          = 0x4f
	DbiStickersFavedLimit      = 0x50
	DbiSuggestStickersByEmoji  = 0x51
	DbiSuggestEmoji            = 0x52
	DbiTxtDomainString         = 0x53
	DbiThemeKey                = 0x54
	DbiTileBackground          = 0x55
	DbiCacheSettings           = 0x56
	DbiAnimationsDisabled      = 0x57
	DbiScalePercent            = 0x58
	DbiPlaybackSpeed           = 0x59
	DbiLanguagesKey            = 0x5a
	DbiEncryptedWithSalt       = 333
	DbiEncrypted               = 444
	DbiVersion                 = 666
)

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

type MediaKey struct {
	LocationType uint32
	DC           int32
	ID           uint64
}

func (d MediaKey) MarshalJSON() ([]byte, error) {
	var locationType string
	switch d.LocationType {
	case 0x4e45abe9:
		locationType = "DocumentFileLocation"
	case 0x74dc404d:
		locationType = "AudioFileLocation"
	case 0x3d0364ec:
		locationType = "VideoFileLocation"
	case 0xcbc7ee28:
		locationType = "SecureFileLocation"
	default:
		locationType = fmt.Sprintf("0x%x", d.LocationType)
	}
	return json.Marshal(struct {
		LocationType string
		DC           int32
		ID           string
	}{
		locationType,
		d.DC,
		fmt.Sprintf("0x%x", d.ID),
	})
}

type Locations struct {
	FullLen   uint32 `struc:"little"`
	Locations []Location
}
type Location struct {
	MediaKey   MediaKey
	LegacyType uint32
	Filename   string
	Bookmark   []byte
	DateTime   time.Time
	Size       uint32
}

type Images struct {
	FullLen    uint32 `struc:"little"`
	First      uint64
	Second     uint64
	LegacyType uint32
	Len        uint32 `struc:"sizeof=Data"`
	Data       []byte `json:"-"`
}

type StickerImages struct {
	FullLen uint32 `struc:"little"`
	First   uint64
	Second  uint64
	Len     uint32 `struc:"sizeof=Data"`
	Data    []byte `json:"-"`
}

type Audios struct {
	FullLen uint32 `struc:"little"`
	First   uint64
	Second  uint64
	Len     uint32 `struc:"sizeof=Data"`
	Data    []byte `json:"-"`
}

type ReportSpamStatuses struct {
	FullLen            uint32 `struc:"little"`
	Size               int32  `struc:"sizeof=ReportSpamStatuses"`
	ReportSpamStatuses []ReportSpamStatus
}
type ReportSpamStatus struct {
	Peer   uint64
	Status int32
}

type UserMap struct{}

type Draft struct{}

type DraftPosition struct{}

type RecentStickersOld struct{}

type BackgroundOld struct{}

type UserSettings struct {
	FullLen           uint32 `struc:"little"`
	DbiDcOptionOldOld struct {
		DcId uint32
		Host string
		IP   string
		Port uint32
	}
	DbiDcOptionOld struct {
		DcIdWithShift uint32
		Flags         int32
		IP            string
		Port          uint32
	}
	DbiDcOptions struct {
		Serialized []byte
	}
	DbiChatSizeMax         int32
	DbiSavedGifsLimit      int32
	DbiStickersRecentLimit int32
	DbiStickersFavedLimit  int32
	DbiMegagroupSizeMax    int32
	DbiUser                struct {
		UserId int32
		DcId   uint32
	}
	DbiKey struct {
		DcId int32
		Key  []byte
	}
	DbiMtpAuthorization struct {
		Serialized []byte
	}
	DbiAutoStart              int32
	DbiStartMinimized         int32
	DbiSendToMenu             int32
	DbiUseExternalVideoPlayer int32
	DbiCacheSettings          struct {
		Size int64
		Time int32
	}
	DbiAnimationsDisabled int32
	DbiSoundNotify        int32
	DbiAutoDownload       struct {
		Photo int32
		Audio int32
		Gif   int32
	}
	DbiAutoPlay    int32
	DbiDialogsMode struct {
		Enabled int32
		ModeInt int32
	}
	DbiModerateMode            int32
	DbiIncludeMutedOld         int32
	DbiShowingSavedGifsOld     int32
	DbiDesktopNotify           int32
	DbiWindowsNotificationsOld int32
	DbiNativeNotifications     int32
	DbiNotificationsCount      int32
	DbiNotificationsCorner     int32
	DbiDialogsWidthRatioOld    int32
	DbiLastSeenWarningSeenOld  int32
	DbiAuthSessionSettings     struct {
		V []byte
	}
	DbiWorkMode          int32
	DbiTxtDomainString   string
	DbiConnectionTypeOld struct {
		V        int32
		Host     string
		Port     int32
		User     string
		Password string
	}
	DbiConnectionType int32 //TODO
	DbiThemeKeyOld    uint64
	DbiThemeKey       struct {
		KeyDay    uint64
		KeyNight  uint64
		NightMode uint32
	}
	DbiLangPackKey     uint64
	DbiLanguagesKey    uint64
	DbiTryIPv6         int32
	DbiSeenTrayTooltip int32
	DbiAutoUpdate      int32
	DbiLastUpdateCheck int32
	DbiScaleOld        int32
	DbiScalePercent    int32
	DbiLangOld         int32
	DbiLangFileOld     string
	DbiWindowPosition  struct {
		X         int
		Y         int
		W         int
		H         int
		Moncrc    int32
		Maximized int
	}
	DbiLoggedPhoneNumber string
	DbiMutePeer          uint64
	DbiMutedPeers        struct {
		Count uint32 `struc:"sizeof=Peers"`
		Peers []uint64
	}
	DbiSendKeyOld        int32
	DbiCatsAndDogs       int32
	DbiTileBackgroundOld int32
	DbiTileBackground    struct {
		TileDay   int32
		TileNight int32
	}
	DbiAdaptiveForWide        int32
	DbiAutoLock               int32
	DbiReplaceEmoji           int32
	DbiSuggestEmoji           int32
	DbiSuggestStickersByEmoji int32
	DbiDefaultAttach          int32
	DbiNotifyView             int32
	DbiAskDownloadPath        int32
	DbiDownloadPathOld        string
	DbiDownloadPath           struct {
		V        string
		Bookmark []byte
	}
	DbiCompressPastedImage int32
	DbiEmojiTabOld         int32
	DbiRecentEmojiOldOld   []struct {
		First  uint32
		Second uint16
	}
	DbiRecentEmojiOld []struct {
		First  uint64
		Second uint16
	}
	DbiRecentEmoji []struct {
		First  string
		Second uint16
	}
	DbiRecentStickers []struct {
		First  uint64
		Second uint16
	}
	DbiEmojiVariantsOld []struct {
		First  uint32
		Second uint64
	}
	DbiEmojiVariants []struct {
		First  string
		Second uint16
	}
	DbiHiddenPinnedMessages []struct {
		PeerId uint64
		MsgId  int32
	}
	DbiDialogLastPath string
	DbiSongVolume     int32
	DbiVideoVolume    int32
	DbiPlaybackSpeed  int32
}

type RecentHashtagsAndBots struct{}

type StickersOld struct{}

type SavedPeers struct{}

type SavedGifsOld struct{}

type SavedGifs struct{}

type StickersKeys struct{}

type TrustedBots struct{}

type FavedStickers struct{}

type ExportSettings struct{}

type Background struct{}

type SelfSerialized struct{}
