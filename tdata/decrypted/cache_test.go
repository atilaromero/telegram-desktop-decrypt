package decrypted

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/atilaromero/telegram-desktop-decrypt/tdata"
	"github.com/atilaromero/telegram-desktop-decrypt/tdata/encrypted"
	"github.com/lunixbochs/struc"
)

const hexImage = "54444624ff4d0f00000002909c8a84b063c3cd78ef081d3eec229e8e43aee25f1252e00f68ed8d10d18574145545ae8d1eecce050863f192aa542168c794770fb45ad011083e1439622574ec4c9a73c07769d29f3042492178844d6d872065086243eb9c944a0ba4a566036cab1f0afa6890314b73452e83ec224d15642b6ceca400e0e661842d4ad2caa3972a1277c28982ae7b92eb1bf451f468a5b2ad088c77d48ef805243e5a8532b6ca420ddedbed22f9f1cbdd1ad971b18f08a1b33b1e7f5d2e51dc1aba8b2e0816d3ebbfefab4e1ca9f0f25d699a9b523629960f7a8b46e2616eeb612167379345dc8ea66d2e4bf6e74433fc5488484d11c3224ac07c6f1ec9e3299e7b816ae37f3c655871a1238e876a0ed9bbb42d787c30ddcb03a59bfcac6df20dfa9e3e92a63622ab9061f1934c3e20ecda3059df099728cff274ad83b6d25f7497e30ef4c4b7f8f3c2fa7ade66fe93b4e17f85d6c8b834c5ee95c40abd6a9e775dd3c2ae22508d68f1d4bdb389eb5d2aea1b71b3a0da14a5a8ce49b84202f3d7fd126ec8f8a270e85b1d8c91f78d71278f5a29062e1b74c5d3e7fc2d0ed82a92c046ca78b9f94d4302424718dfc489c3cfa76098dd05ed18a77b596308408ef9f90f464f389008af2c4d07e1b9f460d2027875335ddcb075714e22bae896ba5a5a05e3bbc8c9e88624e75bc711133bf49ab6e779307d759613318497845ceb7422254edaf5cab968a28423e4ac26edbfd9a590d58ff46a87d827bd61190ff0c4ac344e51cf951ebc78a64440d340a562bf47ecde2d922df93e54e314afa825a1ccb2c995800d2a374cdddb2789eaeeaeaebb31bfc6cf019f518d484397844584ba5595b5e1a7209b549bcfb74131224ba70d57e5b43240539bc47069ad1369b2f01a69ea73a41980930e00392050d8ff72a8b04f826b7b268d67ffbb8c87eecf7e481ed26858"

const hexKey = "4dd3f7947d2f92c5802f2e05cb27520e6a169cdffc071cfcecb2c60c6b1b14152e52afeb5f6e224bb609389187e10d8ed78e6fd8688121783c0ce4dccf816c1e0da13b974d52974b23a7601059393b9f78f0d238c13a957e8da4495d42f4e8be233ef04f08ba9603a681b709512cb2b2b60fb81f4ac515f81fb3d9ed85227732e267ba4d0b005e2df1fcb8afbfc751186b381cc917a9eb665ac1e555a9742acf848756b665164ad6918e578c21fd72c94db48fe291626932e6498d3786b8db45d172acc2b223bd2694dc36d8c219795619018c7adeb6bbbee9b74d28dbf3c1ec87be76da05e6d67cff34dc491c9c88e2d2b4fbdf4637d1bcedfbafb2c8cf0cf34fb82034b1afcad38ee310ce"

func ExampleReadCache() {
	image0, err := hex.DecodeString(hexImage)
	if err != nil {
		fmt.Println(err)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		fmt.Println(err)
	}
	rawtdf, err := tdata.ReadRawTDF(bytes.NewReader([]byte(image0)))
	if err != nil {
		fmt.Println(err)
	}
	ecache, err := encrypted.ReadECache(rawtdf)
	if err != nil {
		fmt.Println(err)
	}
	data, err := ecache.Decrypt(key)
	if err != nil {
		fmt.Println(err)
	}
	cache, err := ReadCache(data, ReverseLSK(Images{}))
	if err != nil {
		fmt.Println(err)
	}
	image := cache.(Images)
	err = struc.Unpack(bytes.NewReader(data), &image)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(image.Data))
	// Output:
	// ffd8ffe000104a46494600010101004800480000ffdb0043000e0a0b0d0b090e0d0c0d100f0e11162417161414162c20211a24342e3736332e32323a4153463a3d4e3e32324862494e56585d5e5d3845666d655a6c535b5d59ffdb0043010f10101613162a17172a593b323b5959595959595959595959595959595959595959595959595959595959595959595959595959595959595959595959595959ffc00011080020005a03012200021101031101ffc400190000030101010000000000000000000000010204030007ffc400351000010302020705050900000000000000010002110312043105132141515291227192a1d2233233d1f042536162638193b1e1ffc40014010100000000000000000000000000000000ffc4001511010100000000000000000000000000000011ffda000c03010002110311003f00f49424252e9902d3fba59a633b5a78142b491c576c3b2520b098007447b0d76401ee409a81f79533e64daafceff126b9bcc3aaeb9bcc3aa0cf51fa957c4b502042ecd720e596b2adf1632d9ceedcb5201cc4a018d19040a5ce00ec64ee177f89c64858de099023410609247926fac966e6bc35e581ae7fd9b8c058df8d9f8543f91de9414900882011f884440c879294d4c5813aaa3dd7bbd281763af814f0f11bdeef920afeb25ca51531b13a9a1ddac77a5173f1922da34403c6a3bd2837820f6623815d2e8f776f9292ed2371ec616d0799d97446ec7961f678704e46f76cef1082a17ef0d464f2a901d21116618bb8dce8fe90bf48449a787f13fe482c93b9bd51513ce91221a30cd24672e31e4aca61c29b43c82f81711bca0fffd9
}

func ExampleReadCache_1() {
	data, err := hex.DecodeString("ac0200000000000500000000000000210000000000000038000000010000002200000e10000000130000000100000052000000010000005100000001000000080000000100000031000000010000000b000000010000001c00000000000000440000000000000045000000030000004600000002000000140000000000000033ffffffffffffffff0000002300000030002f0068006f006d0065002f006100740069006c0061002e0061006c0072002f0050006900630074007500720065007300000029000dbba000000042000dbba0000000340000000000000000000000000000004000000000000000000000004100000000000000370000000100000049000000000000004d0000003800000000000000000000000000000000000000000000000100000004000000000000000000000000000735b700000000ffffffff000000000000003a0000002200000004d83dde02000100000004d83dde180001000000022764000100000004d83dde0d000100000004d83dde0a000100000004d83dde01000100000004d83ddc4d000100000002263a000100000004d83dde14000100000004d83dde04000100000004d83dde2d000100000004d83ddc8b000100000004d83dde12000100000004d83dde33000100000004d83dde1c000100000004d83dde48000100000004d83dde09000100000004d83dde03000100000004d83dde22000100000004d83dde1d000100000004d83dde31000100000004d83dde21000100000004d83dde0f000100000004d83dde1e000100000004d83dde05000100000004d83dde1a000100000004d83dde4a000100000004d83dde0c000100000004d83dde00000100000004d83dde0b000100000004d83dde06000100000004d83ddc4c000100000004d83dde10000100000004d83dde1500010000003b0000000000000026000000003ab23fdf")
	if err != nil {
		fmt.Println(err)
	}
	code := ReverseLSK(UserSettings{})
	cache, err := ReadCache(data, code)
	if err != nil {
		fmt.Println(err)
	}
	json.NewEncoder(os.Stdout).Encode(cache)
	// Output:
	// blockID not found: 984760287
	// {"FullLen":2885812224,"DbiDcOptionOldOld":{"DcId":0,"Host":"","IP":"","Port":0},"DbiDcOptionOld":{"DcIdWithShift":0,"Flags":0,"IP":"","Port":0},"DbiDcOptions":{"Serialized":null},"DbiChatSizeMax":0,"DbiSavedGifsLimit":0,"DbiStickersRecentLimit":0,"DbiStickersFavedLimit":0,"DbiMegagroupSizeMax":0,"DbiUser":{"UserId":0,"DcId":0},"DbiKey":{"DcId":0,"Key":null},"DbiMtpAuthorization":{"Serialized":null},"DbiAutoStart":0,"DbiStartMinimized":0,"DbiSendToMenu":0,"DbiUseExternalVideoPlayer":0,"DbiCacheSettings":{"Size":0,"Time":0},"DbiAnimationsDisabled":0,"DbiSoundNotify":1,"DbiAutoDownload":{"Photo":0,"Audio":0,"Gif":0},"DbiAutoPlay":1,"DbiDialogsMode":{"Enabled":0,"ModeInt":0},"DbiModerateMode":0,"DbiIncludeMutedOld":1,"DbiShowingSavedGifsOld":0,"DbiDesktopNotify":1,"DbiWindowsNotificationsOld":0,"DbiNativeNotifications":0,"DbiNotificationsCount":3,"DbiNotificationsCorner":2,"DbiDialogsWidthRatioOld":0,"DbiLastSeenWarningSeenOld":0,"DbiAuthSessionSettings":{"V":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAHNbcAAAAA/////wAAAAA="},"DbiWorkMode":0,"DbiTxtDomainString":"","DbiConnectionTypeOld":{"V":0,"Host":"","Port":0,"User":"","Password":""},"DbiConnectionType":0,"DbiThemeKeyOld":0,"DbiThemeKey":{"KeyDay":0,"KeyNight":0,"NightMode":0},"DbiLangPackKey":0,"DbiLanguagesKey":0,"DbiTryIPv6":0,"DbiSeenTrayTooltip":0,"DbiAutoUpdate":0,"DbiLastUpdateCheck":0,"DbiScaleOld":0,"DbiScalePercent":0,"DbiLangOld":0,"DbiLangFileOld":"","DbiWindowPosition":{"X":0,"Y":0,"W":0,"H":0,"Moncrc":0,"Maximized":0},"DbiLoggedPhoneNumber":"","DbiMutePeer":0,"DbiMutedPeers":{"Count":0,"Peers":null},"DbiSendKeyOld":0,"DbiCatsAndDogs":0,"DbiTileBackgroundOld":0,"DbiTileBackground":{"TileDay":0,"TileNight":0},"DbiAdaptiveForWide":1,"DbiAutoLock":3600,"DbiReplaceEmoji":1,"DbiSuggestEmoji":1,"DbiSuggestStickersByEmoji":1,"DbiDefaultAttach":0,"DbiNotifyView":0,"DbiAskDownloadPath":0,"DbiDownloadPathOld":"","DbiDownloadPath":{"V":"","Bookmark":""},"DbiCompressPastedImage":0,"DbiEmojiTabOld":0,"DbiRecentEmojiOldOld":null,"DbiRecentEmojiOld":null,"DbiRecentEmoji":[{"First":"😂","Second":1},{"First":"😘","Second":1},{"First":"❤","Second":1},{"First":"😍","Second":1},{"First":"😊","Second":1},{"First":"😁","Second":1},{"First":"👍","Second":1},{"First":"☺","Second":1},{"First":"😔","Second":1},{"First":"😄","Second":1},{"First":"😭","Second":1},{"First":"💋","Second":1},{"First":"😒","Second":1},{"First":"😳","Second":1},{"First":"😜","Second":1},{"First":"🙈","Second":1},{"First":"😉","Second":1},{"First":"😃","Second":1},{"First":"😢","Second":1},{"First":"😝","Second":1},{"First":"😱","Second":1},{"First":"😡","Second":1},{"First":"😏","Second":1},{"First":"😞","Second":1},{"First":"😅","Second":1},{"First":"😚","Second":1},{"First":"🙊","Second":1},{"First":"😌","Second":1},{"First":"😀","Second":1},{"First":"😋","Second":1},{"First":"😆","Second":1},{"First":"👌","Second":1},{"First":"😐","Second":1},{"First":"😕","Second":1}],"DbiRecentStickers":[],"DbiEmojiVariantsOld":null,"DbiEmojiVariants":[],"DbiHiddenPinnedMessages":null,"DbiDialogLastPath":"/home/atila.alr/Pictures","DbiSongVolume":900000,"DbiVideoVolume":900000,"DbiPlaybackSpeed":0}
}

const locationsHex = "70b904003d0364ec0000000102e181950000037d40bc6f52000000880043003a002f00550073006500720073002f00620062002f0044006f0077006e006c006f006100640073002f00540065006c0065006700720061006d0020004400650073006b0074006f0070002f0076006900640065006f005f0032003000310036002d00310031002d00300032005f00320031002d00320030002d00350033002e006d006f0076ffffffff000000000025805f049649dbff002a958f3d0364ec0000000103567448000003da40bc6f52000000880043003a002f00550073006500720073002f00620062002f0044006f0077006e006c006f006100640073002f00540065006c0065006700720061006d0020004400650073006b0074006f0070002f0076006900640065006f005f0032003000310036002d00300039002d00300037005f00320030002d00350034002d00350037002e006d006f0076ffffffff0000000000258027047f5a2aff0036c28b3d0364ec0000000103567448000003f840bc6f52000000880043003a002f00550073006500720073002f00620062002f0044006f0077006e006c006f006100640073002f00540065006c0065006700720061006d0020004400650073006b0074006f0070002f0076006900640065006f005f0032003000310036002d00300038002d00300031005f00320031002d00340035002d00330036002e006d006f0076ffffffff0000000000258002"

func ExampleReadCache_2() {
	data, err := hex.DecodeString(locationsHex)
	if err != nil {
		fmt.Println(err)
	}
	code := ReverseLSK(Locations{})
	cache, err := ReadCache(data, code)
	if err != nil {
		fmt.Println(err)
	}
	json.NewEncoder(os.Stdout).Encode(cache)
	// Output:
	// {"FullLen":1891173376,"Locations":[{"First":4396468626018795521,"Second":207589534785864573,"LegacyType":1086091090,"Len":136,"Filename":"C:/Users/bb/Downloads/Telegram Desktop/video_2016-11-02_21-20-53.mov","Bookmark":[255,255,255,255,0],"Date":629169924,"Time":2521422847,"Size":2790799},{"First":4396468626018795521,"Second":240507482697368538,"LegacyType":1086091090,"Len":136,"Filename":"C:/Users/bb/Downloads/Telegram Desktop/video_2016-09-07_20-54-57.mov","Bookmark":[255,255,255,255,0],"Date":629155588,"Time":2136615679,"Size":3588747}]}
}
