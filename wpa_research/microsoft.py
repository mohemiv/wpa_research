import hashlib;
import hmac;

from struct import pack;

def nt_hash(str, binary=False):
    if binary == False:
        str = str.encode("utf-16le");

    return hashlib.new("md4", str).digest();

def sha1(str):
    return hashlib.new("sha1", str).digest();

# RFC 4306 2.13
def prf_peap_plus (secret, label, seed, length, peap_version = 0):
    if length >= 256:
        raise Exception("length value must be no greater than 255");

    seed = label + seed;

    res = "";
    prev = ""
    i = 0;

    if peap_version == 0:
        prefix = "";
        postfix = "\x00\x00"
    elif peap_version == 1:
        prefix = pack('B', length);
        postfix = "";
    else:
      raise Exception("peap_version value must be 0 or 1");

    while len(res) < length:
        i += 1;
        prev = hmac.new(secret, prev + seed + prefix + pack('B', i) + postfix, hashlib.sha1).digest();
        res += prev;

    return res[:length];
