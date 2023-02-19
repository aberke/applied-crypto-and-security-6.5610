# Tested with python >= 3.8.10
import secrets

# read file in binary mode
def read_file(fn):
    with open(fn, "rb") as f:
        return f.read()

# read the dictionary file
def read_dictionary():
    with open("1000_dict.txt", "r") as f:
        return f.read().split()

# convert strings to ints to apply xor operation
def to_ints(s):
    return [b for b in bytes(s, encoding="ascii")]

# only makes sense if w1 and w2 have the same length
def xor(w1, w2):
    return [w1[i] ^ w2[i] for i in range(min(len(w1), len(w2)))]

# function used for encryption
def encipher(message, randomness):
    # randomness = secrets.token_bytes(len(message))
    return xor(to_ints(message), randomness)


# --------------------------
# Above code was provided

def decrypt(c_bytes, r):
    m_bytes = xor(c_bytes, r)
    m = ''.join(chr(b) for b in m_bytes)
    return m


def get_word_beginnings(dictionary, l):
    """
    Returns a set of word beginnings up to l letters from dictionary
    Excludes words with less than l letters
    e.g. dictionary has ['a','as','are','arduino', ....]
    l=2 --> returns {'as','ar',....}
    """
    return {d[:l] for d in dictionary if len(d) >= l}


if __name__ == "__main__":
    c1 = read_file("c1.bin")
    c2 = read_file("c2.bin")
    num_bytes = len(c1)
    assert(len(c1)==len(c2))
    print('messages are length %s bytes' % num_bytes)

    # This dictionary has only 1,000 words, and the messages are guaranteed to come from them
    dictionary = read_dictionary()
    """ 
    the msg is length 35 bytes
    8 bits in a byte; 2**8 = 256 possible bytes
    256**35 = way too many messages

    we only care about lowercase letters and the space. we know those codes.
    there are only 27 of them
    27**35 = still too many
    but can maybe find smarter ways to handle combinatorics:
    - iterate through possible random bytes strings from start to end of string
    - check if decrypted message up to i is in the dictionary for both c1, c2
    - if yes: continue with the string; otherwise: stop with this string
    - built recursively
    """

    SPACE_DEC_CODE = 32
    dec_codes = [SPACE_DEC_CODE] + list(range(97, 123))

    # for each byte in r[num_bytes]: collect list of elibible bytes
    possible_bytes = []
    for bi in range(num_bytes):
        pbs = []
        for pb in range(256):
            if ((c1[bi]^pb in dec_codes) and (c2[bi]^pb in dec_codes)):
                pbs += [pb]
        possible_bytes += [pbs]


    def check_possible_bytes(accum_bytes, c1_w_idx, c2_w_idx):
        """
        Recursive function
        c1_w_idx, c2_w_idx: indicate index where current word begins
        """
        bi = len(accum_bytes)
        # success case
        if bi == len(c1):
            return [accum_bytes]

        results = []
        pbs = possible_bytes[bi]
        for pi, pb in enumerate(pbs):
            p_accum_bytes = accum_bytes + [pb]
            assert(len(c1[c1_w_idx:bi+1]) == len(p_accum_bytes[c1_w_idx:]))
            assert(len(c2[c2_w_idx:bi+1]) == len(p_accum_bytes[c2_w_idx:]))
            c1_accum_word = decrypt(c1[c1_w_idx:bi+1], p_accum_bytes[c1_w_idx:])
            c2_accum_word = decrypt(c2[c2_w_idx:bi+1], p_accum_bytes[c2_w_idx:])
            
            c1_accum_check = False
            c2_accum_check = True # for testing
            c1_w_idx_next = c1_w_idx
            c2_w_idx_next = c2_w_idx
            if (c1_accum_word[-1] == ' '):
                c1_w_idx_next = bi + 1
                c1_accum_check = c1_accum_word[:-1] in dictionary
            else:
                l = (bi + 1) - c1_w_idx
                c1_accum_check = c1_accum_word in get_word_beginnings(dictionary, l)
            
            if (c2_accum_word[-1] == ' '):
                c2_w_idx_next = bi + 1
                c2_accum_check = c2_accum_word[:-1] in dictionary
            else:
                l = (bi + 1) - c2_w_idx
                c2_accum_check = c2_accum_word in get_word_beginnings(dictionary, l)

            if not (c1_accum_check and c2_accum_check):
                continue
            res = check_possible_bytes(p_accum_bytes, c1_w_idx_next, c2_w_idx_next)
            if len(res) > 0:
                results += res
        return results

    results = check_possible_bytes([], 0, 0)
    print('%s possible results' % len(results))

    for secret in results:
        print('with secret:')
        print(secret)
        print('c1:')
        print(decrypt(c1[:len(secret)], secret))
        print('c2:')
        print(decrypt(c2[:len(secret)], secret))
