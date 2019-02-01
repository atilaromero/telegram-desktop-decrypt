package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"

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
			tdatafile, err := ReadTdataFile(f)
			if err != nil {
				log.Fatal(err)
			}
			tdatafile.Print(verbose)
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
			settings, err := ReadTdataSettings(f)
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
			settings, err := ReadTdataSettings(f)
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
			tdatamap, err := ReadTdataMap(f)
			if err != nil {
				log.Fatalf("could not interpret map file: %v", err)
			}
			localkey, err := tdatamap.GetKey(password)
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
			tdatamap, err := ReadTdataMap(f)
			if err != nil {
				log.Fatal(err)
			}
			localkey, err := tdatamap.GetKey(password)
			if err != nil {
				log.Fatal(err)
			}
			decrypted, err := tdatamap.Decrypt(localkey)
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(decrypted)
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
			tdatamap, err := ReadTdataMap(f)
			if err != nil {
				log.Fatal(err)
			}
			localkey, err := tdatamap.GetKey(password)
			if err != nil {
				log.Fatal(err)
			}
			listedkeys, err := tdatamap.ListKeys(localkey)
			if err != nil {
				log.Fatal(err)
			}
			for k, v := range listedkeys {
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
			tdata, err := ReadTdataFile(f)
			if err != nil {
				log.Fatalf("error reading tdata file: %v", err)
			}
			var streamdata []byte
			r := bytes.NewReader(tdata.Data)
			for i := 0; i <= stream; i++ {
				streamdata, err = ReadStream(r)
				if err != nil {
					log.Fatalf("could not read stream %d: %v", i, err)
				}
			}
			decrypted, err := DecryptLocal(streamdata, key)
			if err != nil {
				log.Fatalf("could not decrypt file: %v", err)
			}
			os.Stdout.Write(decrypted)
		},
	}
	cmdDecrypt.Flags().IntVarP(&stream, "stream", "s", 0, "stream number (default=0)")
	rootCmd.AddCommand(cmdDecrypt)

	cmdBulkDecrypt := &cobra.Command{
		Use:   "bulkdecrypt [map file] [outdir]",
		Short: "decrypt all files in map folder and save results on outdir",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			mappath := args[0]
			outdir := args[1]
			srcdir, err := filepath.Abs(mappath)
			if err != nil {
				log.Fatal(err)
			}
			srcdir = filepath.Dir(srcdir)
			f, err := os.Open(mappath)
			if err != nil {
				log.Fatalf("could not open file '%s': %v", mappath, err)
			}
			defer f.Close()
			tdatamap, err := ReadTdataMap(f)
			if err != nil {
				log.Fatal(err)
			}
			localkey, err := tdatamap.GetKey(password)
			if err != nil {
				log.Fatal(err)
			}
			err = tdatamap.BulkDecrypt(localkey, srcdir, outdir, verbose)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	cmdBulkDecrypt.Flags().StringVarP(&password, "password", "p", "", "optional password (default='')")
	cmdBulkDecrypt.Flags().BoolVarP(&verbose, "verbose", "v", false, "show content of streams")
	rootCmd.AddCommand(cmdBulkDecrypt)

	rootCmd.Execute()
}
