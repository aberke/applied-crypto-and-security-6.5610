import gzip
import requests
import os

# Fill in your kerberos here
KERBEROS="your-kerberos"

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


if __name__ == "__main__":
    # http://leaky.csail.mit.edu/encrypt?kerb=test&msg=hellow-world
    query_server(KERBEROS, "Hi")