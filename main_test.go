package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

func ExampleCreateLocalKey() {
	salt, err := hex.DecodeString("b0ca901027e08bc58296fa67d2e2383f2e62ff5feecc38fb0939d2a9cc2d4561")
	if err != nil {
		log.Fatal(err)
	}
	settingsKey := CreateLocalKey([]byte{}, salt)
	fmt.Println(hex.EncodeToString(settingsKey[:]))
	// Output:
	// f0b32257268466df8e2c6eb865711350659e03a6765b2d388ec40fa7a267ba6c55e65c8b78f3986a6cf8ba94db76c3e8527af6e0de62d5112253d001909e4757e035a1d78548c71dcd6d400a8cbd0b7aad3ae814bf043f2c874011e66d5ba2c512f2590104df08b9a9f29a004324499a91d97778b0a8824a556ab66d0964085387a213bcbb114de85c0a49dc07a51baafaf8ca411b725f0cd083dda703506cfa9c85124f79db7b751a9c157223b829347bf279faccf8ca484e5ac9113cce223fd6bab4c10501ad859002dce92a7c5118da795d37f177180078815bc4718851b2255be5a44bf5049211d5fd2e085a1b01d45df9c3d0d06a7d3618b359e91fab71
}

func TestPrepareAESOldmtp(t *testing.T) {
	cases := []struct {
		globalKey string
		msgKey    string
		key       string
		iv        string
	}{
		{
			"172f55c5cfc4b6256bf183623aa25384f46c59256d0fbc772fdb5a1612f312d7878c57769c00ec8329781140e8e765c526e4ec460d8cc741b10dca90b56131e1b03dc0466b1453ebb9f5d8889e19919027fd06afa165088bd2636c1c7c3df9725b0b9b31c665b34d3351cca5dd626c1cdea216378566e815e53dfca661e6de892d67b833d191f21d",
			"961e4dfa328436a2245d7028ee919890",
			"b3225965bbb000023db5b25b18130cd1e331a2408d12e8c3af2b3f89a5588729",
			"07698990318f43a8ec049647a4332451105870ef00496cfa07e27741368d97ef",
		},
		{
			"f0b32257268466df8e2c6eb865711350659e03a6765b2d388ec40fa7a267ba6c55e65c8b78f3986a6cf8ba94db76c3e8527af6e0de62d5112253d001909e4757e035a1d78548c71dcd6d400a8cbd0b7aad3ae814bf043f2c874011e66d5ba2c512f2590104df08b9a9f29a004324499a91d97778b0a8824a556ab66d0964085387a213bcbb114de8",
			"965de3cb9a78821c6b112cd0548c4b6e",
			"0b6166bbca23cdb152f4207c8ed6744d162e358c1cd992c46e73efe599cf067a",
			"124436550c3ed988f1ee64ee36878f5516ea6b92f43e05c7af445e4d4e3af248",
		},
		{
			"f0b32257268466df8e2c6eb865711350659e03a6765b2d388ec40fa7a267ba6c55e65c8b78f3986a6cf8ba94db76c3e8527af6e0de62d5112253d001909e4757e035a1d78548c71dcd6d400a8cbd0b7aad3ae814bf043f2c874011e66d5ba2c512f2590104df08b9a9f29a004324499a91d97778b0a8824a556ab66d0964085387a213bcbb114de8",
			"94f85a1bc7a9a528a36404b57c89d193",
			"6947a41539482e54eb57550a31de5d388180f6bb49ad374ce9fe3abb2e2fba24",
			"00ff7d54192032f67324cb2a2e7dbab9984514cb1f3ea960bd67ac90aae87e69",
		},
	}
	for _, tt := range cases {
		_globalKey, err := hex.DecodeString(tt.globalKey)
		if err != nil {
			t.Fatal(err, tt.globalKey)
		}
		_msgKey, err := hex.DecodeString(tt.msgKey)
		if err != nil {
			t.Fatal(err, tt.msgKey)
		}
		_key, _iv := PrepareAESOldmtp(_globalKey, _msgKey)
		key := hex.EncodeToString(_key)
		iv := hex.EncodeToString(_iv)
		if tt.key != key {
			t.Errorf("key: expected %s, got %s", tt.key, key)
		}
		if tt.iv != iv {
			t.Errorf("iv: expected %s, got %s", tt.iv, iv)
		}
	}
}
