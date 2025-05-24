# securefs

`securefs` is a simple FUSE-based encrypted virtual file system that protects file contents using AES-256 encryption. All files are transparently encrypted and stored with a `.sec` extension in a designated backend directory.

## Features

* AES-256-CBC encryption for file contents
* Password-derived encryption key using PBKDF2 (HMAC-SHA256)
* Files are stored encrypted under `backend/` with a `.sec` extension
* Basic file operations supported:

  * Create
  * Read
  * Write
  * Delete
  * Directory listing (read-only)

## Requirements

* Linux
* FUSE3
* OpenSSL

Install required packages:

```bash
sudo apt install libfuse3-dev libssl-dev
```

## Build

```bash
gcc `pkg-config fuse3 --cflags` securefs.c -o securefs `pkg-config fuse3 --libs` -lcrypto
```

or

```bash
make
```

## Usage

1. Create a mount point:

```bash
mkdir ~/secure_mount
```

2. Run the filesystem:

```bash
./securefs ~/secure_mount
```

3. In another terminal, use the filesystem:

```bash
echo "hello" > ~/secure_mount/test.txt
cat ~/secure_mount/test.txt
```

Encrypted files will be saved in the backend directory as `test.txt.sec`.

## Password Handling

* The password is prompted on startup and used to derive a 256-bit key using PBKDF2.
* A static salt is used for simplicity (can be improved for production).

## Limitations

* Only flat files are supported (no nested directories).
* Files are assumed to be small (<4KB) for demonstration purposes.

## Contributing

Contributions and bug reports are welcome. Feel free to open issues or submit pull requests.
