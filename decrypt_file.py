from Crypto.Cipher import AES
import os,string,math,sys,shutil
holdrand = None
alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
CRYPTED_EXTENSION = ".[embrace@airmail.cc].embrace"
POSTFIX_SIZE = 512
ENCRYPTION_SIZE_LIMIT = 0x100000
SPECIAL_EXTENTIONS = [".sql", ".mdf", ".txt", ".dbf", ".ckp", ".dacpac", ".db3", ".dtxs", ".mdt", ".sdf", ".MDF", ".DBF"]

def print_help():
    print "Usage: %s <filename> [time of the encryption in seconds]" % sys.argv[0]
    print
    print "To work, the last 16 characters of the encrypted file's path (including the file's name) must be the same as when the file was encrypted"
    print "If this condition is not met, only the 16 first bytes of the file at most will be destroyed"
    

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
    filename = filename.replace(".[embrace@airmail.cc].embrace", "")
    IV = derive_IV_from_filename(filename)
    size_to_decrypt = (len(filecontent) / 16) * 16
    aes = AES.new(init_keys(time), AES.MODE_CBC, derive_IV_from_filename(filename))
    plain = aes.decrypt(filecontent[:size_to_decrypt]) + filecontent[size_to_decrypt:]
    return plain

def test():
    for i in range(100000):
        test_content = "mqkjrzprlghplzrhkajhglkhrlkjgriuhgairhglkjh"
        test_filename = "kikoo.txt"

        locked_content = encrypt_file(test_content, test_filename, i)
        locked_filename = test_filename + ".[embrace@airmail.cc].embrace"
        locked_content += "a"*POSTFIX_SIZE

        plain = decrypt_file(locked_content, locked_filename, i)
        assert(plain == test_content)

def entropy(string):
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
        return entropy

def try_unlock(filename, righttime=None, delta=1000, distance=entropy):
    original_size = os.path.getsize(filename) - POSTFIX_SIZE
    with open(filename, 'rb') as f:
        if (original_size < ENCRYPTION_SIZE_LIMIT) or (os.path.splittext(filename) in SPECIAL_EXTENTIONS):
            filecontent = f.read(original_size)
        else:
            filecontent = f.read(ENCRYPTION_SIZE_LIMIT)
    filetime = int(os.path.getmtime(filename))
    filesize = len(filecontent)
    print "File name: %s, encrypted size: %s, last modification time: %s " % (filename, filesize, filetime)
    
    if righttime is not None:
        return decrypt_file(filecontent, filename, righttime)
    
    print "[+] You did not provide the exact time of the attack "
    closest = 2<<128
    besttime = 0
    for time in range(filetime - delta/2, filetime + delta/2):
        plain = decrypt_file(filecontent, filename, time)
        dist = distance(plain)
        if dist < closest:
            besttime = time
            closest = dist
            print "Timestamp tested:", besttime, "entropy: ", closest, repr(plain[:30])
    print "The right time seems to be %s" % besttime
    print "Use it to decrypt every other files in the same machine"
    print_help()
    return decrypt_file(filecontent, filename, besttime)

if len(sys.argv) < 2:
    print_help()
    exit()

filename = sys.argv[1]
filename = os.path.abspath(filename)

if not filename.endswith(CRYPTED_EXTENSION):
    print "File name should end with %s " % CRYPTED_EXTENSION
    exit()
    
if len(sys.argv) >= 3:
    decrypted_content = try_unlock(filename, righttime=int(sys.argv[2]))
else:
    decrypted_content = try_unlock(filename)

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
