# embrace_decryptor
Decryption tool for the "Embrace", "PainLocker" and "Everbe" ransomwares files (with extensions ```.[embrace@airmail.cc].embrace```, ```.[pain@cock.lu].pain``` and ```.[everbe@airmail.cc].everbe```)

The tool exploits several weaknesses in the malware to recover the files:
* Only one AES key is generated for every file on a same host
* During key-generation, the malware uses the weak ```msvcrt```'s ```rand()``` function, which is not cryptographically secure
* The random generator is seeded using ```srand(time(0))```
* The IV is derived from the last 16 characters of the encrypted file path, which are known even after encryption
* AES mode of operation used is CBC : decrypting a file using the correct key but the wrong IV still leads to full file recovery (minus the first 16 bytes at most).

This decryption tool works as follows:
* It bruteforces the probable value of the original ```time(0)```, using the file's last modification time as a hint
* For each value, it generates an AES key using the derivation algorithm present in the malware, and try to decrypt the file with it
* The tool computes the avererage Shannon's entropy per byte of the decryption result.
  * A high value of entropy (~8 bits by byte) indicates a "random" result, likely to be the product of a decryption with a wrong key.
  * A lesser value indicates "non-random" content (text content, or binary file with structured headers), which means the the right key has been found.

Once one file has been decrypted, the initial value of ```time(0)``` is known, and so the corresponding generated AES key. This key can then be reused to decrypt instantaneously any other file on the same infected machine.

## Script usage
```
usage: decrypt_file.py [-h] [-l LOCALTIME | -t TIME] [-d DELTA] [-v] [-o]
                       [-e EXTENSION] [-r]
                       file [file ...]

Decrypt .embrace ransomware files

positional arguments:
  file                  file(s) to decrypt

optional arguments:
  -h, --help            show this help message and exit
  -l LOCALTIME, --localtime LOCALTIME
                        time of the encryption (local time, format YYYY-MM-DD-
                        hh-mm-ss), if known. Can be approximative if you pass
                        the --delta argument
  -t TIME, --time TIME  time of the encryption (in seconds since Epoch), if
                        known. Can be approximative if you pass the --delta
                        argument
  -d DELTA, --delta DELTA
                        number of seconds to bruteforce, around the provided
                        encryption time, or the file's last modification date
  -v, --verbose         verbose mode
  -o, --overwrite       automatically overwrite decrypted files. Ex: after
                        decryption of xxx.ext..[embrace@airmail.cc].embrace,
                        xxx.ext will be overwritten
  -e EXTENSION, --extension EXTENSION
                        manually provide the encrypted file extension. The
                        tool currently supports
                        ".[embrace@airmail.cc].embrace" (default),
                        ".[everbe@airmail.cc].everbe" and
                        ".[pain@cock.lu].pain"
  -r, --recursive       performs decryption recursively on folders

For this tool to work, the last 16 characters of the encrypted file's path
(including the file's name, without '.[embrace@airmail.cc].embrace') must be
the same as when the file was encrypted If this condition is not met, only the
16 first bytes of the file at most will be destroyed. The rest of the file
will be correctly decrypted.
```
