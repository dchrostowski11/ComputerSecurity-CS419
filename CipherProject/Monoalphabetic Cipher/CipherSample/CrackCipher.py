import sys

def main():
    ciphertext = sys.argv[1]
    knowntext = sys.argv[2]

    knownfreqs = {}
    cipherfreqs = {}

    known_file = open(knowntext, 'r')
    known = []

    for line in known_file:
        known.append(line)

    for i in range(0, len(known)):
        sentence = known[i].lower()

        for char in sentence:
            asciival = ord(char)

            if asciival >= 97 and asciival <= 122:
                knownfreqs[chr(asciival)] = knownfreqs.get(chr(asciival), 0) + 1
            elif asciival == 32:
                knownfreqs[chr(asciival)] = knownfreqs.get(chr(asciival), 0) + 1
            else:
                continue

    cipher_file = open(ciphertext, 'r')
    cipher = []

    for line in cipher_file:
        cipher.append(line)

    for i in range(0, len(cipher)):
        sentence = cipher[i].lower()

        for char in sentence:
            asciival = ord(char)
            if asciival >= 97 and asciival <= 122:
                cipherfreqs[chr(asciival)] = cipherfreqs.get(chr(asciival), 0) + 1
            elif asciival == 32:
                cipherfreqs[chr(asciival)] = cipherfreqs.get(chr(asciival), 0) + 1
            else:
               continue

    knownlist = []
    cipherlist = []

    for key, value in knownfreqs.items():
        temp = [key, value]
        knownlist.append(temp)

    for key, value in cipherfreqs.items():
        temp = [key, value]
        cipherlist.append(temp)

    knownlist = sorted(knownlist, key=lambda x:x[1], reverse=True)

    cipherlist = sorted(cipherlist, key=lambda x:x[1], reverse=True)

    possibleCiphers = []

    for i in range(0, len(cipher)):
        sentence = cipher[i].lower()

        possibleCipher = []

        temp = ""

        for j in sentence:

            asciival = ord(j)

            if asciival >= 97 and asciival <= 122:
                for k in range(0, len(cipherlist)):
                    if cipherlist[k][0] == j:
                        temp = temp + knownlist[k][0]

            elif asciival == 32:
                for k in range(0, len(cipherlist)):
                    if cipherlist[k][0] == j:
                        temp = temp + knownlist[k][0]

            else:
                temp = temp + j

        possibleCiphers.append(temp)

    message = ''.join(possibleCiphers)

    print(message)

main()