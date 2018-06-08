# embrace_decryptor
Decryption tool for the "Embrace" ransomware, might work as well (with adjustments) for the same malware family (Everbe ?)

The exploit several weaknesses in the malware to recover the files:
* Only one AES key is generated for every file on a same host
* During key-generation, the malware uses the weak ```msvcrt```'s ```rand()``` function, which is not cryptographically secure
* The random generator is seeded using ```srand(time(0))```
* The IV is derived from the last 16 characters of the encrypted file path, which are known even after encryption

This decryption tool works as follows:
* It bruteforces the probable value of the original ```time(0)```, using the file's last modification time as a hint
* For each value, it generates an AES key using the derivation algorithm present in the malware, and try to decrypt the file with it
* The tool uses Shannon entropy of the decryption result to find the most promising one. This general method works particularly well on every uncompressed/unencrypted file, whose content clearly differs from random bytes (obtained by AES decryption with a wrong key).

Once one file has been decrypted, the initial value of ```time(0)``` is known, and can be reused to decrypt instantaneously any other file on the same infected machine.

## Script usage
```
python decrypt_file.py <filename> [timestamp of the execution of the malware, if computed]
```
