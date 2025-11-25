from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("userA_private.pem", "wb") as f:
        f.write(private_key)
    with open("userA_public.pem", "wb") as f:
        f.write(public_key)

def encrypt_message():
    message = open("message.txt", "r").read().encode()
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    with open("encrypted_message.bin", "wb") as f:
        f.write(cipher_aes.nonce + tag + ciphertext)
    public_key = RSA.import_key(open("userA_public.pem", "rb").read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_key)

def decrypt_message():
    private_key = RSA.import_key(open("userA_private.pem", "rb").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = open("aes_key_encrypted.bin", "rb").read()
    aes_key = cipher_rsa.decrypt(encrypted_key)
    data = open("encrypted_message.bin", "rb").read()
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    with open("decrypted_message.txt", "wb") as f:
        f.write(message)

if __name__ == "__main__":
    generate_rsa_keys()
    encrypt_message()
    decrypt_message()
