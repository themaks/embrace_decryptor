#!/usr/bin/python2
from Crypto.Cipher import AES
import os
import string
import math
import sys
import shutil
import argparse
import time

holdrand = None
alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
CRYPTED_EXTENSION = ".[embrace@airmail.cc].embrace"
POSTFIX_SIZE = 512
ENCRYPTION_SIZE_LIMIT = 0x100000
SPECIAL_EXTENTIONS = [".sql", ".mdf", ".txt", ".dbf", ".ckp", ".dacpac", ".db3", ".dtxs", ".mdt", ".sdf", ".MDF", ".DBF"]
VERBOSE = False
MAX_ANALYZED_SIZE = 1024 # only check the first 4KB for decryption during key bruteforcing
TMP_EXTENSION = ".tmp_decrypted"

def print_verbose(s):
    global VERBOSE
    if VERBOSE:
        print s

def uint32(n):
    return n & 0xFFFFFFFF
def uint64(n):
    return n & 0xFFFFFFFFFFFFFFFF
def uint128(n):
    return n & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
def str_to_bytes(s):
    return map(ord, s)
def bytes_to_str(b):
    return "".join(map(chr, b))

def srand(seed):
    global holdrand
    holdrand = uint32(seed)

def rand():
    global holdrand
    holdrand  = uint32(0x343fd * holdrand + 0x269ec3)
    return (holdrand >> 16) & 0x7FFF

def init_keys(time):
    global alphabet
    srand(time)
    random_32_chars_id = []
    for _ in range(32):
        r = rand() #r is 32 bits
        tmp = (0x842108421084211 * r) >> 64 # tmp is 32 bits
        random_32_chars_id.append(alphabet[r - 62 * ((tmp + (uint64(r-tmp) >> 1)) >> 5)])
    return "".join(random_32_chars_id)

def pad_or_trunk(content, content_size):
    if content_size >= 16:
        content_size_to_encrypt = content_size - (content_size % 16)
    else: # content_size < 16
        content_size_to_encrypt = content_size
        missing_bytes_for_one_block = 16 - content_size
        i = 0
        while i < missing_bytes_for_one_block:
            content.append(missing_bytes_for_one_block)
            i += 1
    return content_size_to_encrypt

def derive_IV_from_filename(filename):
    filename = filename.replace(os.path.sep, "\\") # linux compatibility
    filename = str_to_bytes(filename)
    filename_16_last_rev = filename[-16:][::-1]
    for k in range(1, 16):
        if k >= len(filename_16_last_rev):
            break
        filename_16_last_rev[k] += k ^ filename_16_last_rev[k]
    if len(filename_16_last_rev) < 16:
        pad_or_trunk(filename_16_last_rev, len(filename_16_last_rev))
    assert (len(filename_16_last_rev)==16)
    return bytes_to_str(filename_16_last_rev)

def encrypt_filecontent(filecontent, filename, time):
    IV = derive_IV_from_filename(filename)
    size_to_encrypt = pad_or_trunk(filecontent, len(filecontent))
    aes = AES.new(init_keys(time), AES.MODE_CBC, derive_IV_from_filename(filename))
    cipher = aes.encrypt(filecontent[:size_to_encrypt]) + filecontent[size_to_encrypt:]
    return cipher

def decrypt_filecontent(filecontent, filename, time):
    filename = filename.replace(CRYPTED_EXTENSION, "")
    IV = derive_IV_from_filename(filename)
    size_to_decrypt = (len(filecontent) / 16) * 16
    aes = AES.new(init_keys(time), AES.MODE_CBC, derive_IV_from_filename(filename))
    plain = aes.decrypt(filecontent[:size_to_decrypt]) + filecontent[size_to_decrypt:]
    return plain

def decrypt_file(filename, size_to_decrypt, time):
    out_filename = filename + TMP_EXTENSION
    in_file = open(filename, "rb")
    out_file = open(out_filename, "wb")
    filename = filename.replace(CRYPTED_EXTENSION, "")
    IV = derive_IV_from_filename(filename)
    aes = AES.new(init_keys(time), AES.MODE_CBC, derive_IV_from_filename(filename))
    chunk_size = 1024 * 1024 # arbitrary
    remaining_size_to_decrypt = size_to_decrypt
    while remaining_size_to_decrypt:
        to_read = min(chunk_size, remaining_size_to_decrypt)
        chunk = in_file.read(to_read)
        decrypted_chunk = aes.decrypt(chunk)
        out_file.write(decrypted_chunk)
        remaining_size_to_decrypt -= to_read
    shutil.copyfileobj(in_file, out_file)
    out_file.seek(-POSTFIX_SIZE, os.SEEK_END)
    out_file.truncate()
    out_file.close()
    in_file.close()
    return out_filename

def entropy(string):
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
        return entropy

def bruteforce_encryption_time(filecontent, basetime, filename, delta, distance):
    closest = 2<<128
    besttime = 0
    bestplain = ""
    start = basetime - delta/2
    end = basetime + delta/2
    print_verbose("[+] Trying every possible encryption time between %d and %d (in seconds since Epoch)" % (start, end))
    for time in range(start, end):
        plain = decrypt_filecontent(filecontent, filename, time)
        dist = distance(plain)
        if dist < closest:
            besttime = time
            bestplain = plain
            closest = dist
    print_verbose("\tBruteforce results:")
    print_verbose("\t"*2 + "Probable timestamp of the encryption date: %d" % besttime)
    print_verbose("\t"*2 + "Average entropy per byte: %s" % closest)
    print_verbose("\t"*2 + "Start of the decrypted file: %s" %repr(bestplain[:30]))
    return besttime

def try_unlock_file(filename, decryptiontime=None, delta=None, distance=entropy):
    original_size = os.path.getsize(filename) - POSTFIX_SIZE
    with open(filename, 'rb') as f:
        filestart = f.read(MAX_ANALYZED_SIZE)
        if (original_size <= ENCRYPTION_SIZE_LIMIT) or os.path.splitext(filename) in SPECIAL_EXTENTIONS:
            size_to_decrypt = (original_size / 16) * 16
        else:
            size_to_decrypt = (ENCRYPTION_SIZE_LIMIT / 16) * 16
    filetime = int(os.path.getmtime(filename))

    if decryptiontime is not None and delta is None:
        return decrypt_file(filename, size_to_decrypt, decryptiontime)

    if delta is None:
        delta = 1000

    if decryptiontime is None:
        print "[-] You did not provide the time of the attack."
        print_verbose("[+] Trying the %d possible values arount the file's last modification date" % delta)
        basetime = filetime
    else:
        print_verbose("[+] Trying the %d possible values arount the provided date" % delta)
        basetime = decryptiontime

    besttime = bruteforce_encryption_time(filestart, basetime, filename, delta, distance)
    decrypted_file_name = decrypt_file(filename, size_to_decrypt, besttime)
    with open(decrypted_file_name, "rb") as decrypted_file:
        decrypted_file_start = decrypted_file.read(30)
        print "[+] The encryption time seems to be %s (in seconds since Epoch) or %s in local time" % (besttime, time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(besttime)))
        print "[+] Use it to decrypt every other files in the same machine (cf. help)"
        print "[+] PLEASE CHECK THE DECRYPTED FILE CONTENT. Discard this result if the decrypted file content is not consistent with the file type."
        print "[+] Decrypted file starts with %s " % repr(decrypted_file_start)
    return decrypted_file_name

def valid_date(s):
    try:
        return time.strptime(s, "%Y-%m-%d-%H-%M-%S")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)

def process_file(filename, args):
    filename = os.path.abspath(filename)
    basename = os.path.basename(filename).replace(CRYPTED_EXTENSION, "")
    print "[+] Decrypting file %s" % filename

    if len(basename) < 15:
        print "[!] WARNING: Make sure the last 16 characters of the file path (not counting '%s') are the same as when the file was encrypted" % CRYPTED_EXTENSION
        start = "[!] ex: "
        print start + filename
        critical_part_size = 15 - len(basename)
        print " " * (len(filename) - len(CRYPTED_EXTENSION) - 16 + len(start)) + "^" * critical_part_size + " especially these characters"

    if args.localtime is not None:
        decryptiontime = int(time.mktime(args.localtime))
    else:
        decryptiontime = args.time

    decrypted_filename = try_unlock_file(filename, decryptiontime=decryptiontime, delta=args.delta)

    new_filename = filename.replace(CRYPTED_EXTENSION, "")
    if os.path.isfile(new_filename) and not args.overwrite:
        print "[?] File %s already exists. Overwrite ? [Y/n]" % new_filename
        if "n" in raw_input().lower():
            os.remove(decrypted_filename)
            print "[!] Skipping %s" % new_filename
            return
    print "[+] Writing decoded file in %s" % new_filename
    if os.path.exists(new_filename):
        os.remove(new_filename)
    os.rename(decrypted_filename, new_filename)

def parse_args():
    parser = argparse.ArgumentParser(description="Decrypt .embrace ransomware files", epilog="For this tool to work, the last 16 characters of the encrypted file's path (including the file's name, without '%s') must be the same as when the file was encrypted\r\nIf this condition is not met, only the 16 first bytes of the file at most will be destroyed. The rest of the file will be correctly decrypted." % CRYPTED_EXTENSION)
    parser.add_argument('file', type=str, nargs='+', help='file(s) to decrypt')
    timearg = parser.add_mutually_exclusive_group()
    timearg.add_argument('-l', '--localtime', type=valid_date, help='time of the encryption (local time, format YYYY-MM-DD-hh-mm-ss), if known. Can be approximative if you pass the --delta argument')
    timearg.add_argument('-t', '--time', type=int, help='time of the encryption (in seconds since Epoch), if known. Can be approximative if you pass the --delta argument')
    parser.add_argument('-d', '--delta', type=int, help='number of seconds to bruteforce, around the provided encryption time, or the file\'s last modification date')
    parser.add_argument('-v', '--verbose', help='verbose mode', action="store_true")
    parser.add_argument('-o', '--overwrite', help='automatically overwrite decrypted files. Ex: after decryption of xxx.ext%s, xxx.ext will be overwritten' % CRYPTED_EXTENSION, action="store_true")
    parser.add_argument('-e', '--extension', help='manually provide the encrypted file extension. The tool currently supports ".[embrace@airmail.cc].embrace" (default), ".[everbe@airmail.cc].everbe" and ".[pain@cock.lu].pain"')
    parser.add_argument('-r', '--recursive', help='performs decryption recursively on folders', action="store_true")

    return parser.parse_args()


args = parse_args()

VERBOSE = args.verbose

if args.extension is not None:
    CRYPTED_EXTENSION = args.extension

if args.recursive and not ((args.time is not None or args.localtime is not None) and args.delta is None):
    print "[!] It is not a good idea to perform recursive decription without providing the exact encryption time, as it would perform a brute force attack on every file"
    print "[!] Instead, first launch the tool on a specific file with the following command to get the exact encryption time:"
    print "\t %s \\" % sys.argv[0]
    print "\t\t--time/--localtime <approximative time of encryption>\\"
    print "\t\t--delta <uncertainty of the provided encryption time in seconds> \\"
    print "\t\t<file name>"
    print
    print "[!] Then, note the computed encryption time returned by the tool, and check the content of the decrypted file."
    print "[!] If the file has been recovered correctly, you can use recursive decryption safely:"
    print "\t %s \\" % sys.argv[0]
    print "\t\t--time/--localtime <exact encryption time returned by the tool> \\"
    print "\t\t--recursive \\"
    print "\t\t--extension <encrypted file extension> \\"
    print "\t\t<folder name>"
    exit(-1)

for file_or_dir_name in args.file:
    if os.path.isdir(file_or_dir_name):
        dirname = file_or_dir_name
        if args.recursive:
            for (root, dirs, files) in os.walk(dirname):
                for f in files:
                    filename = os.path.join(root, f)
                    if filename.endswith(CRYPTED_EXTENSION):
                        process_file(filename, args)
                        print
        else:
            print "%s is a directory. Provide --recursive if you want recursive decryption. Skipping ..." % dirname
            print
        continue

    if not os.path.isfile(file_or_dir_name):
        print "Not a valid file or directory: '%s'. Skipping ..." % file_or_dir_name
        print
        continue
    filename = file_or_dir_name
    if not filename.endswith(CRYPTED_EXTENSION):
        print "Not a valid filename: '%s', should end in %s. Skipping ..." % (filename, CRYPTED_EXTENSION)
        print
        continue
    process_file(filename, args)
    print
