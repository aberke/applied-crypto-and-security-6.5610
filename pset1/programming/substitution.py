# Tested with python >= 3.8.10

# read file in binary mode
def read_file(fn):
    with open(fn, "rb") as f:
        return f.read()

# A function to try a guess
def try_substitution(substitutes, cipher):
    out = ""
    for b in cipher:
        if b in substitutes:
            out += " " + substitutes[b]
        else:
            out += " " + str(b)
    return out

if __name__ == "__main__":
    cipher = read_file("substitution.bin")
    # A freebie
    print(try_substitution({58: 'a'}, cipher))
    # TODO: determine the substitution cipher