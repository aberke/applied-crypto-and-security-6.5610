import gzip
import random # For testing
import requests
import os

# Fill in your kerberos here
# KERBEROS = "test" # server secret: Z3r0 knowled$3 << cute!
KERBEROS = "aberke" # server secret: U$3 3nCrypt10n


################################
# Skeleton code provided
################################
try:
    # To get this package,
    # Create a new python virtual environment
    # https://www.geeksforgeeks.org/create-virtual-environment-using-venv-python/
    # pip3 install pycryptodome
    # or the equivalent for your package manager
    # It conflicts with pycrypto package
    # but, it's not critical for your attack
    from Crypto.Cipher import AES
    ENCRYPT = True
except ImportError:
    # Skip encryption step - not needed for attack
    print("Skipping encryption")
    ENCRYPT = False

# Set to false to run against remote server
LOCAL = True

# The url of the server
URL = "http://leaky.csail.mit.edu/encrypt"

# Secret for local testing of your program
# Set local to false to query server
# Real server has rate-limiting
LOCAL_SECRET = "D01n6 T3$+1^g!"

# The key doesn't actually affect the attack
KEY = os.urandom(16)

# Send a message to the server and get the response
def send_and_recv(kerb, message):
    params = {
        "kerb": kerb,
        "msg": message
    }
    r = requests.get(url=URL, params=params)
    return r.text

# The code that runs on the server
def server_code(_, msg):
    # Of course, this isn't the secret on the server
    to_enc = "Hi %s,\nHear about the new secret going around? It's %s." % (msg, LOCAL_SECRET)
    plaintext = gzip.compress(bytes(to_enc, encoding='utf-8'))
    if ENCRYPT:
        cipher = AES.new(KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return (cipher.nonce + ciphertext + tag).hex()
    else:
        return plaintext

# abstract local and remote queries, for easy testing
# set local to False when you want to run against the real server
def query_server(kerb, message):
    if LOCAL:
        return server_code(kerb, message)
    else:
        return send_and_recv(kerb, message)

################################
# End of skeleton code provided
################################



# The secret consists of ASCII characters from the space character to the lowercase ‘z’ 
# character (numbers 32 to 122 inclusive) and is 14 characters in length.
SECRET_LENGTH = 14
secret_space = [chr(c) for c in range(32, 123)]

# Used for testing
def get_new_secret():
    return "".join(random.sample(secret_space, SECRET_LENGTH))


# Prepend attack messages this very long string to start with 
# '\n' which is not in the secret space.
# Yes could have done this more efficiently but I'm
# going quick and dirty and this is still short
prepend_chars = "\nHear about the new secret going around? It's "

def test_secret_start(m):
    """
    Sends message m to test if it is the start of the secret.
    Returns the length of the response.
    """
    return len(query_server(KERBEROS, prepend_chars + m))    


def hack_the_secret():
    """
    Strategy: 
    prepend with a string that only appears once in the message, before the secret.
    Find the secret from front to back, sending messages prepended with this string.
    """
    m = ""
    for i in range(SECRET_LENGTH):
        char = get_next_char(m)
        m = m + char
    return m


def get_next_char(m):
    for char in secret_space:
        if test_secret_start(m + char) <= 238:
            return char
    # Failure if you get this far


if __name__ == "__main__":
    # http://leaky.csail.mit.edu/encrypt?kerb=test&msg=hellow-world
    # Notes
    # when going from 0 --> 14 front to back (starts with ' ')
    # empty: 234; 1 bit: 236; then each extra seret bit adds nothing
    # each extra non-secret character adds +2 unless it overlaps with
    # other content surrounding the secret

    # Locally test hacking code with multiple (local) secrets
    N_tests = 4
    for t in range(N_tests+1):
        print('Local test %s with secret: %s' % (t, LOCAL_SECRET))
        assert(hack_the_secret() == LOCAL_SECRET) # The test
        # Set up test with new secret
        new_local_secret = get_new_secret()
        assert(len(new_local_secret)==SECRET_LENGTH) # Assert is valid secret length
        LOCAL_SECRET = new_local_secret

    # Attack the server
    print('Attack the server secret')
    LOCAL = False
    secret = hack_the_secret()
    assert(len(secret) == SECRET_LENGTH)
    print('server secret:')
    print(secret)
