# Task 1 – Encrypted Messaging App Prototype

---

## Goal

- Implement a mini encrypted messaging system that supports both RSA and AES

---

## Python Imports

- `from Crypto.PublicKey import RSA`  
- `from Crypto.Cipher import AES, PKCS1_OAEP`  
- `from Crypto.Random import get_random_bytes`

---

## Generate RSA Keys Function

- `def generate_rsa_keys():`  
  - `key = RSA.generate(2048)`  
  - `private_key = key.export_key()`  
  - `public_key = key.publickey().export_key()`  
  - `with open("userA_private.pem", "wb") as f: f.write(private_key)`  
  - `with open("userA_public.pem", "wb") as f: f.write(public_key)`

---

## Encrypt Message Function

- `def encrypt_message():`  
  - `message = open("message.txt", "r").read().encode()`  
  - `aes_key = get_random_bytes(32)`  
  - `cipher_aes = AES.new(aes_key, AES.MODE_EAX)`  
  - `ciphertext, tag = cipher_aes.encrypt_and_digest(message)`  
  - `with open("encrypted_message.bin", "wb") as f: f.write(cipher_aes.nonce + tag + ciphertext)`  
  - `public_key = RSA.import_key(open("userA_public.pem", "rb").read())`  
  - `cipher_rsa = PKCS1_OAEP.new(public_key)`  
  - `encrypted_key = cipher_rsa.encrypt(aes_key)`  
  - `with open("aes_key_encrypted.bin", "wb") as f: f.write(encrypted_key)`

---

## Decrypt Message Function

- `def decrypt_message():`  
  - `private_key = RSA.import_key(open("userA_private.pem", "rb").read())`  
  - `cipher_rsa = PKCS1_OAEP.new(private_key)`  
  - `encrypted_key = open("aes_key_encrypted.bin", "rb").read()`  
  - `aes_key = cipher_rsa.decrypt(encrypted_key)`  
  - `data = open("encrypted_message.bin", "rb").read()`  
  - `nonce = data[:16]`  
  - `tag = data[16:32]`  
  - `ciphertext = data[32:]`  
  - `cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)`  
  - `message = cipher_aes.decrypt_and_verify(ciphertext, tag)`  
  - `with open("decrypted_message.txt", "wb") as f: f.write(message)`

---

## Main Execution

- `if __name__ == "__main__":`  
  - `generate_rsa_keys()`  
  - `encrypt_message()`  
  - `decrypt_message()`

---

## Encryption Flow Summary

- **Overview:**  
  - AES-256 (symmetric) encrypts the message  
  - RSA-2048 (asymmetric) encrypts the AES key  
  - Combines efficiency of symmetric encryption with security of asymmetric key exchange

- **Flow:**  
  1. RSA Key Generation  
     - User A generates RSA-2048 key pair  
     - Public key shared with User B  
     - Private key kept secret  
  2. AES Key Creation  
     - User B generates random AES-256 key  
  3. Message Encryption (AES)  
     - User B encrypts plaintext using AES-256 EAX mode  
     - Output: `encrypted_message.bin`  
  4. AES Key Encryption (RSA)  
     - User B encrypts AES key with User A’s RSA public key  
     - Output: `aes_key_encrypted.bin`  
  5. AES Key Decryption  
     - User A decrypts AES key using RSA private key  
  6. Message Decryption (AES)  
     - User A decrypts message using AES key  
     - Output: `decrypted_message.txt`

---

## Artifacts

- `message.txt`  
- `encrypted_message.bin`  
- `aes_key_encrypted.bin`  
- `decrypted_message.txt`
- `Task1.md`