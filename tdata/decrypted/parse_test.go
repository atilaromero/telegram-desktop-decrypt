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

func ExampleParseCache() {
	image0, err := hex.DecodeString(hexImage)
	if err != nil {
		fmt.Println(1, err)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		fmt.Println(2, err)
	}
	rawtdf, err := tdata.ReadRawTDF(bytes.NewReader([]byte(image0)))
	if err != nil {
		fmt.Println(3, err)
	}
	ecache, err := encrypted.ReadECache(rawtdf)
	if err != nil {
		fmt.Println(4, err)
	}
	data, err := ecache.Decrypt(key)
	if err != nil {
		fmt.Println(5, err)
	}
	cache, err := ParseCache(data, ReverseLSK(Images{}))
	if err != nil {
		fmt.Println(6, err)
	}
	image := cache.(Images)
	err = struc.Unpack(bytes.NewReader(data), &image)
	if err != nil {
		fmt.Println("error using unpack", err)
	}
	fmt.Println(hex.EncodeToString(image.Data))
	// Output:
	// ffd8ffe000104a46494600010101004800480000ffdb0043000e0a0b0d0b090e0d0c0d100f0e11162417161414162c20211a24342e3736332e32323a4153463a3d4e3e32324862494e56585d5e5d3845666d655a6c535b5d59ffdb0043010f10101613162a17172a593b323b5959595959595959595959595959595959595959595959595959595959595959595959595959595959595959595959595959ffc00011080020005a03012200021101031101ffc400190000030101010000000000000000000000010204030007ffc400351000010302020705050900000000000000010002110312043105132141515291227192a1d2233233d1f042536162638193b1e1ffc40014010100000000000000000000000000000000ffc4001511010100000000000000000000000000000011ffda000c03010002110311003f00f49424252e9902d3fba59a633b5a78142b491c576c3b2520b098007447b0d76401ee409a81f79533e64daafceff126b9bcc3aaeb9bcc3aa0cf51fa957c4b502042ecd720e596b2adf1632d9ceedcb5201cc4a018d19040a5ce00ec64ee177f89c64858de099023410609247926fac966e6bc35e581ae7fd9b8c058df8d9f8543f91de9414900882011f884440c879294d4c5813aaa3dd7bbd281763af814f0f11bdeef920afeb25ca51531b13a9a1ddac77a5173f1922da34403c6a3bd2837820f6623815d2e8f776f9292ed2371ec616d0799d97446ec7961f678704e46f76cef1082a17ef0d464f2a901d21116618bb8dce8fe90bf48449a787f13fe482c93b9bd51513ce91221a30cd24672e31e4aca61c29b43c82f81711bca0fffd9
}

func ExampleParseCache_a() {
	data, err := hex.DecodeString("ac0200000000000500000000000000210000000000000038000000010000002200000e10000000130000000100000052000000010000005100000001000000080000000100000031000000010000000b000000010000001c00000000000000440000000000000045000000030000004600000002000000140000000000000033ffffffffffffffff0000002300000030002f0068006f006d0065002f006100740069006c0061002e0061006c0072002f0050006900630074007500720065007300000029000dbba000000042000dbba0000000340000000000000000000000000000004000000000000000000000004100000000000000370000000100000049000000000000004d0000003800000000000000000000000000000000000000000000000100000004000000000000000000000000000735b700000000ffffffff000000000000003a0000002200000004d83dde02000100000004d83dde180001000000022764000100000004d83dde0d000100000004d83dde0a000100000004d83dde01000100000004d83ddc4d000100000002263a000100000004d83dde14000100000004d83dde04000100000004d83dde2d000100000004d83ddc8b000100000004d83dde12000100000004d83dde33000100000004d83dde1c000100000004d83dde48000100000004d83dde09000100000004d83dde03000100000004d83dde22000100000004d83dde1d000100000004d83dde31000100000004d83dde21000100000004d83dde0f000100000004d83dde1e000100000004d83dde05000100000004d83dde1a000100000004d83dde4a000100000004d83dde0c000100000004d83dde00000100000004d83dde0b000100000004d83dde06000100000004d83ddc4c000100000004d83dde10000100000004d83dde1500010000003b0000000000000026000000003ab23fdf")
	if err != nil {
		fmt.Println(err)
	}
	code := ReverseLSK(UserSettings{})
	cache, err := ParseCache(data, code)
	if err != nil {
		fmt.Println(err)
	}
	json.NewEncoder(os.Stdout).Encode(cache)
	// Output:
	// {"FullLen":684,"DbiDcOptionOldOld":{"DcId":0,"Host":"","IP":"","Port":0},"DbiDcOptionOld":{"DcIdWithShift":0,"Flags":0,"IP":"","Port":0},"DbiDcOptions":{"Serialized":null},"DbiChatSizeMax":0,"DbiSavedGifsLimit":0,"DbiStickersRecentLimit":0,"DbiStickersFavedLimit":0,"DbiMegagroupSizeMax":0,"DbiUser":{"UserId":0,"DcId":0},"DbiKey":{"DcId":0,"Key":null},"DbiMtpAuthorization":{"Serialized":null},"DbiAutoStart":0,"DbiStartMinimized":0,"DbiSendToMenu":0,"DbiUseExternalVideoPlayer":0,"DbiCacheSettings":{"Size":0,"Time":0},"DbiAnimationsDisabled":0,"DbiSoundNotify":1,"DbiAutoDownload":{"Photo":0,"Audio":0,"Gif":0},"DbiAutoPlay":1,"DbiDialogsMode":{"Enabled":0,"ModeInt":0},"DbiModerateMode":0,"DbiIncludeMutedOld":1,"DbiShowingSavedGifsOld":0,"DbiDesktopNotify":1,"DbiWindowsNotificationsOld":0,"DbiNativeNotifications":0,"DbiNotificationsCount":3,"DbiNotificationsCorner":2,"DbiDialogsWidthRatioOld":0,"DbiLastSeenWarningSeenOld":0,"DbiAuthSessionSettings":{"V":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAHNbcAAAAA/////wAAAAA="},"DbiWorkMode":0,"DbiTxtDomainString":"","DbiConnectionTypeOld":{"V":0,"Host":"","Port":0,"User":"","Password":""},"DbiConnectionType":0,"DbiThemeKeyOld":0,"DbiThemeKey":{"KeyDay":0,"KeyNight":0,"NightMode":0},"DbiLangPackKey":0,"DbiLanguagesKey":0,"DbiTryIPv6":0,"DbiSeenTrayTooltip":0,"DbiAutoUpdate":0,"DbiLastUpdateCheck":0,"DbiScaleOld":0,"DbiScalePercent":0,"DbiLangOld":0,"DbiLangFileOld":"","DbiWindowPosition":{"X":0,"Y":0,"W":0,"H":0,"Moncrc":0,"Maximized":0},"DbiLoggedPhoneNumber":"","DbiMutePeer":0,"DbiMutedPeers":{"Count":0,"Peers":null},"DbiSendKeyOld":0,"DbiCatsAndDogs":0,"DbiTileBackgroundOld":0,"DbiTileBackground":{"TileDay":0,"TileNight":0},"DbiAdaptiveForWide":1,"DbiAutoLock":3600,"DbiReplaceEmoji":1,"DbiSuggestEmoji":1,"DbiSuggestStickersByEmoji":1,"DbiDefaultAttach":0,"DbiNotifyView":0,"DbiAskDownloadPath":0,"DbiDownloadPathOld":"","DbiDownloadPath":{"V":"","Bookmark":""},"DbiCompressPastedImage":0,"DbiEmojiTabOld":0,"DbiRecentEmojiOldOld":null,"DbiRecentEmojiOld":null,"DbiRecentEmoji":[{"First":"😂","Second":1},{"First":"😘","Second":1},{"First":"❤","Second":1},{"First":"😍","Second":1},{"First":"😊","Second":1},{"First":"😁","Second":1},{"First":"👍","Second":1},{"First":"☺","Second":1},{"First":"😔","Second":1},{"First":"😄","Second":1},{"First":"😭","Second":1},{"First":"💋","Second":1},{"First":"😒","Second":1},{"First":"😳","Second":1},{"First":"😜","Second":1},{"First":"🙈","Second":1},{"First":"😉","Second":1},{"First":"😃","Second":1},{"First":"😢","Second":1},{"First":"😝","Second":1},{"First":"😱","Second":1},{"First":"😡","Second":1},{"First":"😏","Second":1},{"First":"😞","Second":1},{"First":"😅","Second":1},{"First":"😚","Second":1},{"First":"🙊","Second":1},{"First":"😌","Second":1},{"First":"😀","Second":1},{"First":"😋","Second":1},{"First":"😆","Second":1},{"First":"👌","Second":1},{"First":"😐","Second":1},{"First":"😕","Second":1}],"DbiRecentStickers":[],"DbiEmojiVariantsOld":null,"DbiEmojiVariants":[],"DbiHiddenPinnedMessages":null,"DbiDialogLastPath":"/home/atila.alr/Pictures","DbiSongVolume":900000,"DbiVideoVolume":900000,"DbiPlaybackSpeed":0}
}

func ExampleParseCache_b() {
	data, err := hex.DecodeString("ae0000004e45abe9000000014481d5870000003d0000000000000048002f0068006f006d0065002f006100740069006c0061002e0061006c0072002f00500069006300740075007200650073002f00530070006f0074006900660079002e0070006e0067ffffffff000000000025802c02301bbeff0002a38c0000000000000000000000000000000000000000ffffffffffffffff00000000002583c1023ba3e4ff0000000000000000000000000e8e")
	if err != nil {
		fmt.Println(err)
	}
	code := ReverseLSK(Locations{})
	cache, err := ParseCache(data, code)
	if err != nil {
		fmt.Println(err)
	}
	b, err := json.Marshal(cache)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(b))
	// Output:
	// {"FullLen":174,"Locations":[{"MediaKey":{"LocationType":"DocumentFileLocation","DC":1,"ID":"0x4481d5870000003d"},"LegacyType":0,"Filename":"/home/atila.alr/Pictures/Spotify.png","Bookmark":"","DateTime":"2016-09-12T10:11:47.262Z","Size":172940}]}
}

func ExampleParseCache_c() {
	data, err := hex.DecodeString("3203000000000003000000c80000003200030d4000000035000000c800000043000000c80000005000000005000000060000000000000007000000000000001d0000000000000009000000000000000a000000000000000c000000010000000d0000000000000016000000000000004a0000025cffffffff0000000d0000000100000000000001bb0000000e3134392e3135342e3137352e3530000000000000000100000001000001bb00000027323030313a306232383a663233643a663030313a303030303a303030303a303030303a30303061000000000000000200000000000001bb0000000e3134392e3135342e3136372e3531000000000000000200000001000001bb00000027323030313a303637633a303465383a663030323a303030303a303030303a303030303a30303061000000000000000300000000000001bb0000000f3134392e3135342e3137352e313030000000000000000300000001000001bb00000027323030313a306232383a663233643a663030333a303030303a303030303a303030303a30303061000000000000000400000000000001bb0000000e3134392e3135342e3136372e3931000000000000000400000001000001bb00000027323030313a303637633a303465383a663030343a303030303a303030303a303030303a30303061000000000000000400000002000001bb0000000f3134392e3135342e3136342e323530000000000000000400000003000001bb00000027323030313a303637633a303465383a663030343a303030303a303030303a303030303a30303062000000000000000500000001000001bb00000027323030313a306232383a663233663a663030353a303030303a303030303a303030303a30303061000000000000000500000010000001bb0000000d39312e3130382e35362e323030000000000000000500000000000001bb0000000d39312e3130382e35362e3137350000000000000000000000190000001a00350035003500310039003900390037003700390030003700300000004f0000000400000000ffffffff00000028000000010000004ea642b24495ee2a550000000e0000000200000018000004ac0000073ac674053f0000000049fad6985298f9b321101418ed78")

	if err != nil {
		fmt.Println(err)
	}

	cache, err := ParseCache(data, ReverseLSK(UserSettings{}))
	if err != nil {
		fmt.Println(err)
	}
	b, err := json.Marshal(cache)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(b))
	// Output:
	// {"FullLen":818,"DbiDcOptionOldOld":{"DcId":0,"Host":"","IP":"","Port":0},"DbiDcOptionOld":{"DcIdWithShift":0,"Flags":0,"IP":"","Port":0},"DbiDcOptions":{"Serialized":"/////wAAAA0AAAABAAAAAAAAAbsAAAAOMTQ5LjE1NC4xNzUuNTAAAAAAAAAAAQAAAAEAAAG7AAAAJzIwMDE6MGIyODpmMjNkOmYwMDE6MDAwMDowMDAwOjAwMDA6MDAwYQAAAAAAAAACAAAAAAAAAbsAAAAOMTQ5LjE1NC4xNjcuNTEAAAAAAAAAAgAAAAEAAAG7AAAAJzIwMDE6MDY3YzowNGU4OmYwMDI6MDAwMDowMDAwOjAwMDA6MDAwYQAAAAAAAAADAAAAAAAAAbsAAAAPMTQ5LjE1NC4xNzUuMTAwAAAAAAAAAAMAAAABAAABuwAAACcyMDAxOjBiMjg6ZjIzZDpmMDAzOjAwMDA6MDAwMDowMDAwOjAwMGEAAAAAAAAABAAAAAAAAAG7AAAADjE0OS4xNTQuMTY3LjkxAAAAAAAAAAQAAAABAAABuwAAACcyMDAxOjA2N2M6MDRlODpmMDA0OjAwMDA6MDAwMDowMDAwOjAwMGEAAAAAAAAABAAAAAIAAAG7AAAADzE0OS4xNTQuMTY0LjI1MAAAAAAAAAAEAAAAAwAAAbsAAAAnMjAwMTowNjdjOjA0ZTg6ZjAwNDowMDAwOjAwMDA6MDAwMDowMDBiAAAAAAAAAAUAAAABAAABuwAAACcyMDAxOjBiMjg6ZjIzZjpmMDA1OjAwMDA6MDAwMDowMDAwOjAwMGEAAAAAAAAABQAAABAAAAG7AAAADTkxLjEwOC41Ni4yMDAAAAAAAAAABQAAAAAAAAG7AAAADTkxLjEwOC41Ni4xNzUAAAAAAAAAAA=="},"DbiChatSizeMax":200,"DbiSavedGifsLimit":200,"DbiStickersRecentLimit":200,"DbiStickersFavedLimit":5,"DbiMegagroupSizeMax":200000,"DbiUser":{"UserId":0,"DcId":0},"DbiKey":{"DcId":-1,"Key":"AAAAAQAAAE6mQrJEle4qVQAAAA4AAAACAAAAGAAABKwAAAc6xnQFPw=="},"DbiMtpAuthorization":{"Serialized":null},"DbiAutoStart":0,"DbiStartMinimized":0,"DbiSendToMenu":0,"DbiUseExternalVideoPlayer":0,"DbiCacheSettings":{"Size":0,"Time":0},"DbiAnimationsDisabled":0,"DbiSoundNotify":0,"DbiAutoDownload":{"Photo":0,"Audio":0,"Gif":0},"DbiAutoPlay":0,"DbiDialogsMode":{"Enabled":0,"ModeInt":0},"DbiModerateMode":0,"DbiIncludeMutedOld":0,"DbiShowingSavedGifsOld":0,"DbiDesktopNotify":0,"DbiWindowsNotificationsOld":0,"DbiNativeNotifications":0,"DbiNotificationsCount":0,"DbiNotificationsCorner":0,"DbiDialogsWidthRatioOld":0,"DbiLastSeenWarningSeenOld":0,"DbiAuthSessionSettings":{"V":null},"DbiWorkMode":0,"DbiTxtDomainString":"","DbiConnectionTypeOld":{"V":0,"Host":"","Port":0,"User":"","Password":""},"DbiConnectionType":4,"DbiThemeKeyOld":0,"DbiThemeKey":{"KeyDay":0,"KeyNight":0,"NightMode":0},"DbiLangPackKey":0,"DbiLanguagesKey":0,"DbiTryIPv6":0,"DbiSeenTrayTooltip":0,"DbiAutoUpdate":1,"DbiLastUpdateCheck":0,"DbiScaleOld":0,"DbiScalePercent":0,"DbiLangOld":0,"DbiLangFileOld":"","DbiWindowPosition":{"X":0,"Y":0,"W":0,"H":0,"Moncrc":0,"Maximized":0},"DbiLoggedPhoneNumber":"5551999779070","DbiMutePeer":0,"DbiMutedPeers":{"Count":0,"Peers":null},"DbiSendKeyOld":0,"DbiCatsAndDogs":0,"DbiTileBackgroundOld":0,"DbiTileBackground":{"TileDay":0,"TileNight":0},"DbiAdaptiveForWide":0,"DbiAutoLock":0,"DbiReplaceEmoji":0,"DbiSuggestEmoji":0,"DbiSuggestStickersByEmoji":0,"DbiDefaultAttach":0,"DbiNotifyView":0,"DbiAskDownloadPath":0,"DbiDownloadPathOld":"","DbiDownloadPath":{"V":"","Bookmark":null},"DbiCompressPastedImage":0,"DbiEmojiTabOld":0,"DbiRecentEmojiOldOld":null,"DbiRecentEmojiOld":null,"DbiRecentEmoji":null,"DbiRecentStickers":null,"DbiEmojiVariantsOld":null,"DbiEmojiVariants":null,"DbiHiddenPinnedMessages":null,"DbiDialogLastPath":"","DbiSongVolume":0,"DbiVideoVolume":0,"DbiPlaybackSpeed":0}
}
