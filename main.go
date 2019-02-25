package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

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

	var cmdInspect = &cobra.Command{
		Use:   "inspect [tdata file]",
		Short: "inspect tdata file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatal(err)
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
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatal(err)
			}
			settings, err := encrypted.ReadESettings(rawtdf)
			if err != nil {
				log.Fatalf("could not interpret settings file: %v", err)
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
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatal(err)
			}
			settings, err := encrypted.ReadESettings(rawtdf)
			if err != nil {
				log.Fatalf("could not interpret settings file: %v", err)
			}
			settingsKey := settings.GetKey(password)
			decrypted, err := settings.Decrypt(settingsKey)
			os.Stdout.Write(decrypted)
		},
	}
	cmdSettingsDecrypt.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
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
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %v", filename, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatalf("could not interpret map file: %v", err)
			}
			localkey, err := emap.GetKey(password)
			if err != nil {
				log.Fatalf("could not decrypt map file: %v", err)
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
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %v", filename, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatal(err)
			}
			data, err := emap.Decrypt(password)
			if err != nil {
				log.Fatal(err)
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
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %v", filename, err)
			}
			emap, err := encrypted.ReadEMap(rawtdf)
			if err != nil {
				log.Fatal(err)
			}
			data, err := emap.Decrypt(password)
			if err != nil {
				log.Fatal(err)
			}
			dmap, err := decrypted.ReadDMap(data)
			if err != nil {
				log.Fatal(err)
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
				log.Fatalf("invalid key (must be in hex): %v", err)
			}
			f, err := os.Open(filename)
			if err != nil {
				log.Fatalf("could not open file '%s': %v", filename, err)
			}
			defer f.Close()
			rawtdf, err := tdata.ReadRawTDF(f)
			if err != nil {
				log.Fatalf("could not interpret file '%s': %v", filename, err)
			}
			cache, err := encrypted.ReadECache(rawtdf)
			if err != nil {
				log.Fatalf("error reading tdata file: %v", err)
			}
			data, err := decrypt.DecryptLocal(cache.Encrypted, key)
			if err != nil {
				log.Fatalf("could not decrypt file: %v", err)
			}
			os.Stdout.Write(data)
		},
	}
	cmdDecrypt.Flags().IntVarP(&stream, "stream", "s", 0, "stream number (default=0)")
	rootCmd.AddCommand(cmdDecrypt)

	// cmdBulkDecrypt := &cobra.Command{
	// 	Use:   "bulkdecrypt [map file] [outdir]",
	// 	Short: "decrypt all files in map folder and save results on outdir",
	// 	Args:  cobra.ExactArgs(2),
	// 	Run: func(cmd *cobra.Command, args []string) {
	// 		mappath := args[0]
	// 		outdir := args[1]
	// 		srcdir, err := filepath.Abs(mappath)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		srcdir = filepath.Dir(srcdir)
	// 		f, err := os.Open(mappath)
	// 		if err != nil {
	// 			log.Fatalf("could not open file '%s': %v", mappath, err)
	// 		}
	// 		defer f.Close()
	// 		td, err := tdata.ReadRawTDF(f)
	// 		if err != nil {
	// 			log.Fatalf("could not interpret file '%s': %v", mappath, err)
	// 		}
	// 		tmap, err := encrypted.ToTMap(td)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		localkey, err := tmap.GetKey(password)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		err = BulkDecrypt(tmap, localkey, srcdir, outdir)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 	},
	// }
	// cmdBulkDecrypt.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	// rootCmd.AddCommand(cmdBulkDecrypt)

	rootCmd.Execute()
}

// func BulkDecrypt(tdatamap encrypted.TMap, localkey []byte, srcdir string, outdir string) error {
// 	listkeys, err := tdatamap.ListKeys(localkey)
// 	if err != nil {
// 		return err
// 	}
// 	files, err := ioutil.ReadDir(srcdir)
// 	if err != nil {
// 		return err
// 	}
// 	err = os.Mkdir(outdir, 0755)
// 	if err != nil {
// 		return fmt.Errorf("outdir should not exist: %v", err)
// 	}
// 	lf, err := os.Create(path.Join(outdir, "locations.csv"))
// 	if err != nil {
// 		return fmt.Errorf("could not create locations.csv: %v", err)
// 	}
// 	defer lf.Close()
// 	filesf, err := os.Create(path.Join(outdir, "files.csv"))
// 	if err != nil {
// 		return fmt.Errorf("could not create files.csv: %v", err)
// 	}
// 	defer filesf.Close()
// 	for _, fpath := range files {
// 		if fpath.Name() == "map0" || fpath.Name() == "map1" {
// 			continue
// 		}
// 		reversedkey := fpath.Name()[:len(fpath.Name())-1]
// 		key := ""
// 		for _, c := range reversedkey {
// 			key = string(c) + key
// 		}
// 		var typename string
// 		keytype, ok := listkeys[key]
// 		if ok {
// 			typename = encrypted.LSK[keytype]
// 		} else {
// 			typename = "Unknown"
// 		}
// 		keytypepath := path.Join(outdir, typename)
// 		os.Mkdir(keytypepath, 0755) // ignore error
// 		if typename == "Images" {
// 			keytypepath = path.Join(keytypepath, fpath.Name()[:2])
// 			os.Mkdir(keytypepath, 0755) // ignore error
// 		}
// 		encryptedfile := path.Join(srcdir, fpath.Name())
// 		decryptedfile := path.Join(keytypepath, fpath.Name())
// 		f, err := os.Open(encryptedfile)
// 		if err != nil {
// 			log.Fatalf("could not open file '%s': %v", encryptedfile, err)
// 		}
// 		defer f.Close()
// 		td, err := tdata.ReadRawTDF(f)
// 		if err != nil {
// 			log.Fatalf("error reading tdata file: %v", err)
// 		}
// 		f.Close()

// 		data, newlocationIDs, err := encrypted.SaveDecrypted(localkey, td, keytype)
// 		if err != nil {
// 			return err
// 		}
// 		ioutil.WriteFile(decryptedfile, data, 0644)

// 		for _, l := range newlocationIDs {
// 			if l.Filename != "" {
// 				fmt.Fprintf(lf, "%16x\t%16x\t%d\t%s\n", l.First, l.Second, l.Size, l.Filename)
// 			} else {
// 				fmt.Fprintf(filesf, "%16x\t%16x\t%d\t%s\n", l.First, l.Second, l.Size, decryptedfile)
// 			}
// 		}
// 	}
// 	return nil
// }
