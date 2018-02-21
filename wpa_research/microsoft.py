import hashlib
import hmac

from struct import pack


def nt_hash(str, binary=False):
    if binary is False:
        str = str.encode("utf-16le")

    return hashlib.new("md4", str).digest()


def sha1(str):
    return hashlib.new("sha1", str).digest()


# RFC 4306 2.13
def prf_peap_plus(secret, label, seed, length, peap_version=0):
    if length >= 256:
        raise ValueError("length value must be no greater than 255")

    seed = label + seed

    res = ""
    prev = ""
    i = 0

    if peap_version == 0:
        prefix = ""
        postfix = "\x00\x00"
    elif peap_version == 1:
        prefix = pack('B', length)
        postfix = ""
    else:
        raise ValueError("peap_version value must be 0 or 1")

    while len(res) < length:
        i += 1
        prev = hmac.new(secret, prev + seed + prefix + pack('B', i) + postfix, hashlib.sha1).digest()
        res += prev

    return res[:length]


# For MS-CHAP and NTLMv1
# Expand the key from a 7-byte value to a 8-byte value by setting parity bit to 0.
# DES is 56-bit cypher, so DES.new will ignore the parity bit.
# https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Cipher/DES.py#L71
#
# 11111111 11111111 11111111 11111111 11111111 11111111 11111111 =>
# 11111110 11111110 11111110 11111110 11111110 11111110 11111110 11111110

def expand_DES_key(key):
    if len(key) != 7:
        raise ValueError("key must be 7 bytes")

    k1 = ord(key[0])
    k2 = ord(key[1])
    k3 = ord(key[2])
    k4 = ord(key[3])
    k5 = ord(key[4])
    k6 = ord(key[5])
    k7 = ord(key[6])

    ret  = chr( (k1 & 0b11111110) )
    ret += chr( (k1 & 0b00000001) << 7 | (k2 & 0b11111100) >> 1)
    ret += chr( (k2 & 0b00000011) << 6 | (k3 & 0b11111000) >> 2)
    ret += chr( (k3 & 0b00000111) << 5 | (k4 & 0b11110000) >> 3)
    ret += chr( (k4 & 0b00001111) << 4 | (k5 & 0b11100000) >> 4)
    ret += chr( (k5 & 0b00011111) << 3 | (k6 & 0b11000000) >> 5)
    ret += chr( (k6 & 0b00111111) << 2 | (k7 & 0b10000000) >> 6)
    ret += chr( (k7 & 0b01111111) << 1)

    return ret
