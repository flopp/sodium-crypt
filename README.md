# sodium-crypt
libsodium based file encrypter/decrypter

This is just a quick example on how to use `libsodium` for password-based file encryption/decryption.

**DO NOT USE THIS IN PRODUCTION!**

## Build

Make sure, `libsodium` is properly installed.
On Debian/Ubuntu-based systems, a simple `sudo apt install libsodium-dev` should suffice.

Then run

```
make
make test
```

## Use


### Encrypt

```
build/sodium-crypt --encrypt PASSWORD INPUTFILE OUTPUTFILE
```

### Decrypt

```
build/sodium-crypt --decrypt PASSWORD INPUTFILE OUTPUTFILE
```
