import gmpy2
import rsa

EXPONENT = 5
KEYSIZE = 2048

# https://stuvel.eu/python-rsa-doc/reference.html#rsa.newkeys
def generate_keys():
    """Returns a tuple (rsa.PublicKey, rsa.PrivateKey)"""
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
    # -------------------------------------------------
    # Skeleton code above; My(*) code below.
    # (*) Help from https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-2/
    # -------------------------------------------------
    """
    Call secret message m, note EXPONENT e=5
    M = m^(EXPONENT) 
    Need to solve system of equations:
    M ≡ c1 (mod n1)
    M ≡ c2 (mod n2)
    M ≡ c3 (mod n3)
    M ≡ c4 (mod n4)
    M ≡ c5 (mod n5)
    Assume the n_i (pk's) are coprime ==> chinese remainder thrm: unique solution exists
    """
    n1, n2, n3, n4, n5 = moduli
    cs = as_nums
    N = n1*n2*n3*n4*n5
    # N_i = N/n_i: N1 = N/n1, N2 = N/n2, etc
    Ns = [N//moduli[i] for i in range(5)]
    inverses = [gmpy2.invert(Ns[i], moduli[i]) for i in range(5)]
    M = sum([cs[i]*inverses[i]*Ns[i] for i in range (5)]) % N
    m = gmpy2.iroot(M, EXPONENT)[0]
    print('int version of m:')
    print(m)
    print('string:')
    print(str(rsa.transform.int2bytes(int(m))))

broadcast_attack()
