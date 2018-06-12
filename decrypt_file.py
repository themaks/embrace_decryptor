from Crypto.Cipher import AES
import os,string,math,sys,shutil,argparse
holdrand = None
alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
CRYPTED_EXTENSION = ".[embrace@airmail.cc].embrace"
POSTFIX_SIZE = 512
ENCRYPTION_SIZE_LIMIT = 0x100000
SPECIAL_EXTENTIONS = [".sql", ".mdf", ".txt", ".dbf", ".ckp", ".dacpac", ".db3", ".dtxs", ".mdt", ".sdf", ".MDF", ".DBF"]


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

def encrypt_file(filecontent, filename, time):
    IV = derive_IV_from_filename(filename)
    size_to_encrypt = pad_or_trunk(filecontent, len(filecontent))
    aes = AES.new(init_keys(time), AES.MODE_CBC, derive_IV_from_filename(filename))
    cipher = aes.encrypt(filecontent[:size_to_encrypt]) + filecontent[size_to_encrypt:]
    return cipher

def decrypt_file(filecontent, filename, time):
    filename = filename.replace(CRYPTED_EXTENSION, "")
    IV = derive_IV_from_filename(filename)
    size_to_decrypt = (len(filecontent) / 16) * 16
    aes = AES.new(init_keys(time), AES.MODE_CBC, derive_IV_from_filename(filename))
    plain = aes.decrypt(filecontent[:size_to_decrypt]) + filecontent[size_to_decrypt:]
    return plain

def entropy(string):
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
        return entropy

def bruteforce_encryption_time(filecontent, basetime, filename, delta, distance):
    closest = 2<<128
    besttime = 0
    start = filetime - delta/2
    end = filetime + delta/2
    print "[+] Trying every possible encryption time between %d and %d" % (start, end)
    for time in range(start, end):
        plain = decrypt_file(filecontent, filename, time)
        dist = distance(plain)
        if dist < closest:
            besttime = time
            closest = dist
            print "\tTimestamp tested:", besttime, "entropy: ", closest, "decrypted file start: ", repr(plain[:30])

def try_unlock_file(filename, decryptiontime=None, delta=None, distance=entropy):
    original_size = os.path.getsize(filename) - POSTFIX_SIZE
    with open(filename, 'rb') as f:
        if (original_size < ENCRYPTION_SIZE_LIMIT) or (os.path.splitext(filename) in SPECIAL_EXTENTIONS):
            filecontent = f.read(original_size)
        else:
            filecontent = f.read(ENCRYPTION_SIZE_LIMIT)
    filetime = int(os.path.getmtime(filename))
    filesize = len(filecontent)
    print "[+] File name: %s, encrypted size: %s, last modification time: %s " % (filename, filesize, filetime)

    if decryptiontime is not None and delta is None:
        return decrypt_file(filecontent, filename, decryptiontime)

    if delta is None:
        delta = 1000

    if decryptiontime is None:
        print "[-] You did not provide the time of the attack."
        print "[+] Trying the %d possible values arount the file's last modification date" % delta
        basetime = filetime
    else:
        print "[+] Trying the %d possible values arount the provided date" % delta
        basetime = decryptiontime

    besttime = bruteforce_encryption_time(filecontent, basetime, filename, delta, distance)
    print "[+] The encryption time seems to be %s" % besttime
    print "[+] Use it to decrypt every other files in the same machine (cf. help)"
    return decrypt_file(filecontent, filename, besttime)


parser = argparse.ArgumentParser(description="Decrypt .embrace ransomware files", epilog="For this tool to work, the last 16 characters of the encrypted file's path (including the file's name, without '%s') must be the same as when the file was encrypted\r\nIf this condition is not met, only the 16 first bytes of the file at most will be destroyed. The rest of the file will be correctly decrypted." % CRYPTED_EXTENSION)
parser.add_argument('file', nargs='+', help='file(s) to decrypt')
parser.add_argument('--time', type=int, help='timestamp of the encryption (in seconds since Epoch), if known')
parser.add_argument('--delta', type=int, help='number of seconds to bruteforce, around the provided timestamp, or the file\'s last modification date')

args = parser.parse_args()

for filename in args.file:
    filename = os.path.abspath(filename)
    print "[+] Decrypting file %s" % filename
    if not filename.endswith(CRYPTED_EXTENSION):
        print "[-] File name %s should end with %s " % (filename, CRYPTED_EXTENSION)
        print"Skipping..."
        continue

    decrypted_content = try_unlock_file(filename, righttime=args.time)

    new_filename = os.path.split(filename.replace(CRYPTED_EXTENSION, ""))
    new_filename = list(new_filename)
    new_filename[-1] = "decrypted_" + new_filename[-1]
    new_filename = os.sep.join(new_filename)
    with open(new_filename, "wb") as newf:
        with open(filename, "rb") as oldf:
            newf.write(decrypted_content)
            oldf.seek(len(decrypted_content))
            remaining_size = os.path.getsize(filename) - len(decrypted_content) - POSTFIX_SIZE
            shutil.copyfileobj(oldf, newf, remaining_size)
