

<h1>Decryption Tools</h1>

Simple utilities used to decrypt the encrypted `global-metadata.dat` file from the game **Stella Sora**

---

###  How it works

The metadata file begins with a special header:

* Magic `0x1357FEDA` (marks it as encrypted)
* 256-byte key table
* 64-byte bytecode block
* Encrypted payload

Decryption runs per 64-byte chunk, combining:

* byte rotation (`__ROR1__`)
* XOR with values from the key
* small transformations based on the bytecode

The same routine is used by the game itself during startup.

---


###  Usage

```bash
decryptor.exe global-metadata.dat output-metadata.dat
```

