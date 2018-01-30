import hashlib;

def nt_hash(str, binary=False):
    if binary == False:
        str = str.encode("utf-16le");

    return hashlib.new("md4", str).digest();

def sha1(str):
    return hashlib.new("sha1", str).digest();
