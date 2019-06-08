import sys

def main():
    ciphFile = sys.argv[1]
    dictFile = sys.argv[2]

    dictionarytxt = open(dictFile, 'r')
    dictionary = []

    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    for word in dictionarytxt:
        word = word.strip()
        dictionary.append(word)

    cipherFile = open(ciphFile, 'r')
    ciphers = []
    for line in cipherFile:
        if line == '\n':
            continue
        ciphers.append(line)

    possibleCiphers = []

    for offset in range(0,26):
        # go cipher by cipher...
        possibleCipher = []

        for cipher in ciphers:
            temp = ""

            for char in cipher:
                # check to see if char is a letter, if so shift it else just concatenate it
                if char.isalpha():
                    asciival = ord(char)

                    #UPPERCASE
                    if asciival >= 65 and asciival <= 90:
                        char = ALPHABET[((asciival - 65 + offset)%26)]
                        temp = temp + char

                    #lowercase
                    elif asciival >= 97 and asciival <= 122:
                        char = alphabet[((asciival - 97 + offset)%26)]
                        temp = temp + char

                else:
                    temp = temp + char

            possibleCipher.append(temp)

        possibleCiphers.append(possibleCipher)

    index = 0
    max_count = 0

    words = ""

    for i in range(0, 26):
        count = 0
        cipher = possibleCiphers[i]

        for j in range(0, len(cipher)):
            words += ''.join(cipher[j])

        for word in words.split():
            if word in dictionary:
                count += 1
            if count > max_count:
                max_count = count
                index = i

        words = ""

    solution = ''.join(possibleCiphers[index])

    print(solution)

main()