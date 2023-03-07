from datetime import datetime
import math
import secrets

G = 2
# Not a very secure prime - don't use this for anything
P = 115792089237316195423570985008687907853269984665640564039457584007913129870127

# For your testing - generates a random short discrete log
def gen_random_instance(numbits=48):
    m = secrets.randbits(numbits)
    x = pow(G, m, P)
    return (m, x)

def read_inputs():
    with open("inputs.txt", "r") as f:
        return [int(v) for v in f.readlines()]

def get_inverse(x, modulus=P):
    return pow(x, modulus-2, modulus)

def GSBS(p, g, y, msg_max, debug=False):
    """
    Runs the giant-step-baby-step algorithm, as seen in class
    https://65610.csail.mit.edu/2023/lec/l07-key-exchange.pdf
    Returns discrete log for y, using generator g, modulus p.
    """
    p_sqrt = math.ceil(p**(1/2))
    msg_sqrt = math.ceil(msg_max**(1/2))
    # here m refers to the m used in the GSBS algorithm, not the message
    m = min(msg_sqrt, p_sqrt)
    if debug:
        print('%s: p=%s; g=%s; y=%s\np_sqrt=%s\nmsg_sqrt=%s\nm=%s' % (datetime.now(),p,g,y,p_sqrt, msg_sqrt, m))
    # compute L1
    l1_map = dict()
    for i in range(m):
        z = pow(g, i*m, p)
        l1_map[z] = i
    if debug:
        print('%s: computed L1' % datetime.now())
    # L2
    for j in range(p):
        gj = pow(g, j, p)
        gj_inverse = get_inverse(gj, p)
        z = (y * gj_inverse) % p
        if z in l1_map:
            return l1_map[z]*m + j
    print('---- GSBS failure ----')
    return 0

def my_attack(y, numbits):
    """
    My attack uses the GSBS algorithm but shorter.
    y = g**msg
    msg has 48=numbits bits. i.e. msg < 2**48
    log(P,2) = 256. i.e. P ~ 2**256 >> msg = 2**48
    Moreover, 2**48 << P**(1/2)
    So we run the GSBS algorithm using up to sqrt(2**numbits) instead of sqrt(P)
    """
    return GSBS(P, G, y, 2**numbits)

if __name__ == "__main__":
    numbits = 48
    print('%s: attack using numbits=%s' % (datetime.now(), numbits))
    m, x = gen_random_instance(numbits)
    print('%s: testing with random m=%s; x=%s' % (datetime.now(), m, x))
    assert(m < 2**numbits)
    a = my_attack(x, numbits)
    if a != m:
        print("%s: Failure!" % datetime.now())
    else:
        print('%s: Passed the test; running main attack' % datetime.now())
        # My MIT ID # is 914786628
        ID = 914786628
        i = ID % 1000
        x = read_inputs()[i]
        print('%s: ID=%s; i=%s; x=%s' % (datetime.now(), ID, i, x))
        m = my_attack(x, numbits)
        print('%s: result: %s' % (datetime.now(), m))
