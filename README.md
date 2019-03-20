# telegram-desktop-decrypt
Tool to decrypt tdata files.

Telegram Desktop (the one that runs on desktops, not on phones) has a "tdata" folder where it stores some encrypted files.
This folder is normally found at "~/.local/share/TelegramDesktop" on Linux 
and at "%USERPROFILE%\AppData\Roaming\Telegram Desktop" on Windows.

This tool can decrypt those files, which contains settings and cache files, but not chat histories because these are not included in tdata.

## Usage

```
./telegram-desktop-decrypt bulkdecrypt tdata/D877F783D5D3EF8C/map0 outdir
```

This will produce 3 kinds of files:
  - .rawencrypted: decrypted unparsed file
  - .cache: The cache file (may be a JPEG, video, or any type of shared file).
  - .json: settings or metadata about the cache file.
