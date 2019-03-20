package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/atilaromero/telegram-desktop-decrypt/tdata/decrypted"

	"github.com/atilaromero/telegram-desktop-decrypt/tdata/encrypted"

	"github.com/atilaromero/telegram-desktop-decrypt/decrypt"
	"github.com/atilaromero/telegram-desktop-decrypt/tdata"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: os.Args[0]}
	var password string
	var verbose bool
	var stream int
	var parse bool

	var cmdInspect = &cobra.Command{
		Use:   "inspect [tdata file]",
		Short: "inspect tdata file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			rawtdf.Print(verbose)
		},
	}
	cmdInspect.Flags().BoolVarP(&verbose, "verbose", "v", false, "show content of streams")
	rootCmd.AddCommand(cmdInspect)

	cmdSettings := &cobra.Command{
		Use:   "settings [settings file]",
		Short: "work with settings file",
	}
	rootCmd.AddCommand(cmdSettings)
	cmdSettingsKey := &cobra.Command{
		Use:   "getkey [settings file]",
		Short: "get settings key in hex",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			settings, err := encrypted.ReadESettings(rawtdf)
			if err != nil {
				log.Fatalf("could not interpret settings file: %+v", err)
			}
			settingsKey := settings.GetKey(password)
			fmt.Println(hex.EncodeToString(settingsKey))
		},
	}
	cmdSettingsKey.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdSettings.AddCommand(cmdSettingsKey)
	cmdSettingsDecrypt := &cobra.Command{
		Use:   "decrypt [settings file]",
		Short: "decrypt settings file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			settings, err := encrypted.ReadESettings(rawtdf)
			if err != nil {
				log.Fatalf("could not interpret settings file: %+v", err)
			}
			settingsKey := settings.GetKey(password)
			plain, err := settings.Decrypt(settingsKey)
			if !parse {
				os.Stdout.Write(plain)
				return
			}
			parsed, err := decrypted.ParseCache(plain, decrypted.ReverseLSK(decrypted.UserSettings{}))
			if err != nil {
				log.Fatalf("could not interpret settings file: %+v", err)
			}
			m, err := json.Marshal(parsed)
			if err != nil {
				log.Fatalf("could not interpret settings file: %+v", err)
			}
			os.Stdout.Write(m)
		},
	}
	cmdSettingsDecrypt.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdSettingsDecrypt.Flags().BoolVarP(&parse, "parse", "", true, "(default=true)")
	cmdSettings.AddCommand(cmdSettingsDecrypt)

	cmdMap := &cobra.Command{
		Use:   "map [map file]",
		Short: "work with map file",
	}
	rootCmd.AddCommand(cmdMap)
	cmdMapKey := &cobra.Command{
		Use:   "getkey [map file]",
		Short: "get map key in hex",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %+v", filename, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatalf("could not interpret map file: %+v", err)
			}
			localkey, err := emap.GetKey(password)
			if err != nil {
				log.Fatalf("could not decrypt map file: %+v", err)
			}
			fmt.Println(hex.EncodeToString(localkey))
		},
	}
	cmdMapKey.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdMap.AddCommand(cmdMapKey)
	cmdMapDecrypt := &cobra.Command{
		Use:   "decrypt [map file]",
		Short: "decrypt map file",
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %+v", filename, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			data, err := emap.Decrypt(password)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			os.Stdout.Write(data)
		},
	}
	cmdMapDecrypt.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdMap.AddCommand(cmdMapDecrypt)
	cmdMapListKeys := &cobra.Command{
		Use:   "listkeys [map file]",
		Short: "decrypt map and list keys found on it",
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %+v", filename, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			data, err := emap.Decrypt(password)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			dmap, err := decrypted.ReadDMap(data)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			for k, v := range dmap.Files {
				fmt.Println(k, v)
			}
		},
	}
	cmdMapListKeys.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdMap.AddCommand(cmdMapListKeys)

	cmdDecrypt := &cobra.Command{
		Use:   "decrypt [tdata file] [key in hex (only first 136 bytes matter)]",
		Short: "decrypt a regular tdata file",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			key, err := hex.DecodeString(args[1])
			if err != nil {
				log.Fatalf("invalid key (must be in hex): %+v", err)
			}
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %+v", filename, err)
			}
			cache, err := encrypted.ReadECache(rawtdf)
			if err != nil {
				log.Fatalf("error reading tdata file: %+v", err)
			}
			data, err := decrypt.DecryptLocal(cache.Encrypted, key)
			if err != nil {
				log.Fatalf("could not decrypt file: %+v", err)
			}
			os.Stdout.Write(data)
		},
	}
	cmdDecrypt.Flags().IntVarP(&stream, "stream", "s", 0, "stream number (default=0)")
	rootCmd.AddCommand(cmdDecrypt)

	cmdBulkDecrypt := &cobra.Command{
		Use:   "bulkdecrypt [map file] [outdir]",
		Short: "decrypt and parse all files in map folder, and save results in outdir",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			mappath := args[0]
			outdir := args[1]
			srcdir, err := filepath.Abs(mappath)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			srcdir = filepath.Dir(srcdir)
			f, err := os.Open(mappath)
			if err != nil {
				log.Fatalf("could not open file '%s': %+v", mappath, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %+v", mappath, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			d, err := emap.Decrypt(password)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			dmap, err := decrypted.ReadDMap(d)
			if err != nil {
				log.Fatalf("could not decrypt file '%s': %+v", mappath, err)
			}
			localkey, err := emap.GetKey(password)
			if err != nil {
				log.Fatalf("%+v", err)
			}
			err = BulkDecrypt(dmap, localkey, srcdir, outdir, parse)
			if err != nil {
				log.Fatalf("%+v", err)
			}
		},
	}
	cmdBulkDecrypt.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdBulkDecrypt.Flags().BoolVarP(&parse, "parse", "", true, "(default=true)")
	rootCmd.AddCommand(cmdBulkDecrypt)

	rootCmd.Execute()
}

func BulkDecrypt(dmap decrypted.DMap, localkey []byte, srcdir string, outdir string, parse bool) error {
	files, err := ioutil.ReadDir(srcdir)
	if err != nil {
		return err
	}
	err = os.Mkdir(outdir, 0755)
	if err != nil {
		return fmt.Errorf("outdir should not exist: %+v", err)
	}
	for _, fpath := range files {
		if fpath.Name() == "map0" || fpath.Name() == "map1" {
			continue
		}
		fname := fpath.Name()[:len(fpath.Name())-1]
		var typename string
		keytype, ok := dmap.Files[fname]
		if ok {
			typename = reflect.TypeOf(decrypted.LSK[keytype]).Name()
		} else {
			typename = "Unknown"
		}
		keytypepath := path.Join(outdir, typename)
		os.Mkdir(keytypepath, 0755) // ignore error
		encryptedfile := path.Join(srcdir, fpath.Name())
		decryptedfile := path.Join(keytypepath, fpath.Name()+".rawdecrypted")
		f, err := os.Open(encryptedfile)
		if err != nil {
			return fmt.Errorf("could not open file '%s': %+v", encryptedfile, err)
		}
		defer f.Close()
		rawtdf, err := tdata.ReadRawTDF(f)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error reading tdata file %+v", fpath.Name()))
		}
		f.Close()

		ecache, err := encrypted.ReadECache(rawtdf)
		if err != nil {
			log.Fatalf("error reading ecache file: %+v", err)
		}

		rawdecrypted, err := ecache.Decrypt(localkey)
		if err != nil {
			return fmt.Errorf("error decrypting tdata file '%s': %+v", encryptedfile, err)
		}

		ioutil.WriteFile(decryptedfile, rawdecrypted, 0444)

		if !parse {
			continue
		}

		if typename == "Unknown" {
			continue
		}

		if unsafe.Sizeof(decrypted.LSK[keytype]) == 0 {
			continue
		}

		cache, err := decrypted.ParseCache(rawdecrypted, keytype)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error parsing tdata file %s", fpath.Name()))
		}

		decryptedfile = path.Join(keytypepath, fpath.Name()+".cache")
		switch c := cache.(type) {
		case decrypted.Audios:
			ioutil.WriteFile(decryptedfile, c.Data[:c.Len], 0444)
		case decrypted.StickerImages:
			ioutil.WriteFile(decryptedfile, c.Data[:c.Len], 0444)
		case decrypted.Images:
			ioutil.WriteFile(decryptedfile, c.Data[:c.Len], 0444)
		}

		decryptedfile = path.Join(keytypepath, fpath.Name()+".json")
		b, err := json.Marshal(cache)
		if err != nil {
			return fmt.Errorf("could not convert to json '%s': %+v", decryptedfile, err)
		}
		if string(b) != "{}" {
			ioutil.WriteFile(decryptedfile, b, 0444)
		}

	}
	return nil
}
