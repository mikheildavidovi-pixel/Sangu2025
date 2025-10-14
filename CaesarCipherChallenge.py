cipher = "mznxpz"

def caesar_decrypt(ciphertext, shift):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            result += chr((ord(char) - 97 - shift) % 26 + 97)
        else:
            result += char
    return result

for s in range(26):
    print(s, caesar_decrypt(cipher, s))


