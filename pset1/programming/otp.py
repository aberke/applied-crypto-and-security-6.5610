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

if __name__ == "__main__":
    c1 = read_file("c1.bin")
    c2 = read_file("c2.bin")
    # This dictionary has only 1,000 words, and the messages are guaranteed to come from them
    dictionary = read_dictionary()
    # TODO: determine the messages. 