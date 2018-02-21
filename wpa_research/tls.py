import hashlib
import hmac


# RFC 2246 5
# for SSL v3, TLS 1.0, TLS 1.1

def prf_old(secret, label, seed, length):
    key_1 = secret[:((len(secret) + 1) // 2)]
    key_2 = secret[(len(secret) // 2):]

    prf1 = prf_new(key_1, label, seed, hashlib.md5, length)
    prf2 = prf_new(key_2, label, seed, hashlib.sha1, length)

    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(prf1, prf2))


# RFC 5246 5
# for TLS 1.2
def prf_new(secret, label, seed, hash, length):
    seed = label + seed

    res = ""
    a = seed

    while len(res) < length:
        a = hmac.new(secret, a, hash).digest()
        res += hmac.new(secret, a + seed, hash).digest()

    return res[:length]