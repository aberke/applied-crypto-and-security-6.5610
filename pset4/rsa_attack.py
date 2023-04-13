# pip install rsa
import rsa

EXPONENT = 5
KEYSIZE = 2048

def generate_keys():
    return rsa.newkeys(KEYSIZE, exponent=EXPONENT)

# Encrypt without padding
def insecure_encrypt(pub_key, msg):
    payload = rsa.transform.bytes2int(msg)
    encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
    keylength = rsa.common.byte_size(pub_key.n)
    block = rsa.transform.int2bytes(encrypted, keylength)
    return block

# Code used to generate files
def gen_icrt_attack(msg):
    keys = [generate_keys() for _ in range(EXPONENT)]
    ciphertexts = [insecure_encrypt(k[0], msg) for k in keys]
    as_nums = [rsa.transform.bytes2int(c) for c in ciphertexts]
    moduli = [k[0].n for k in keys]
    kf = open("keys.txt", "w")
    kf.writelines([str(pk) + "\n" for pk in moduli])
    cf = open("ciphertexts.txt", "w")
    cf.writelines([str(c) + "\n" for c in as_nums]) 

def broadcast_attack():
    kf = open("keys.txt")
    cf = open("ciphertexts.txt")
    moduli = [int(k) for k in kf.readlines()]
    as_nums = [int(c) for c in cf.readlines()]
    # TODO: your attack
    r = 0


    # Print out string for answer
    print(str(rsa.transform.int2bytes(r)))

broadcast_attack()