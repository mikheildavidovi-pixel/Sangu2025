# Task 2 – Secure File Exchange Using RSA + AES

---

## Objective

- Demonstrate hybrid encryption protocol covered in Week 2 & Week 4

---

## Scenario

- Alice wants to send Bob a secret file securely

---

## Step 1 – Generate an RSA Key Pair for Bob

- **Private Key Command:** `openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048`  
- **Public Key Command:** `openssl pkey -in private.pem -pubout -out public.pem`

---

## Step 2 – Alice Creates a Plaintext Message

- **Command:** `echo "Curiouser and curiouser!" > alice_message.txt`

---

## Step 3 – Generate AES-256 Key and IV

- **AES Key Command:** `openssl rand -out aes_key.bin 32`  
- **IV Command:** `openssl rand -out iv.bin 16`  
- **PowerShell Hex Conversion:**  
  - `(Get-Content "C:\Users\Ronin\aes_key.bin" -Encoding Byte | ForEach-Object { $_.ToString("X2") }) -join "" | Set-Content "C:\Users\Ronin\aes_key.hex"`  
  - `(Get-Content "C:\Users\Ronin\iv.bin" -Encoding Byte | ForEach-Object { $_.ToString("X2") }) -join "" | Set-Content "C:\Users\Ronin\iv.hex"`

---

## Step 4 – Encrypt the File Using AES-256

- **Command:** `openssl enc -aes-256-cbc -in "C:\Users\Ronin\alice_message.txt" -out "C:\Users\Ronin\encrypted_file.bin" -K (Get-Content "C:\Users\Ronin\aes_key.hex") -iv (Get-Content "C:\Users\Ronin\iv.hex")`

---

## Step 5 – Encrypt the AES Key Using Bob’s RSA Public Key

- **Command:** `openssl pkeyutl -encrypt -inkey public.pem -pubin -in aes_key.bin -out aes_key_encrypted.bin -pkeyopt rsa_padding_mode:oaep`

---

## Step 6 – Bob Decrypts the AES Key

- **Command:** `openssl pkeyutl -decrypt -inkey private.pem -in aes_key_encrypted.bin -out aes_key_decrypted.bin -pkeyopt rsa_padding_mode:oaep`  
- **PowerShell Hex Conversion:**  
  - `(Get-Content "C:\Users\Ronin\aes_key_decrypted.bin" -Encoding Byte | ForEach-Object { $_.ToString("X2") }) -join "" | Set-Content "C:\Users\Ronin\aes_key_decrypted.hex"`  
  - `(Get-Content "C:\Users\Ronin\iv.bin" -Encoding Byte | ForEach-Object { $_.ToString("X2") }) -join "" | Set-Content "C:\Users\Ronin\iv.hex"`

---

## Step 7 – Bob Decrypts the File

- **Command:** `openssl enc -d -aes-256-cbc -in "C:\Users\Ronin\encrypted_file.bin" -out "C:\Users\Ronin\decrypted_message.txt" -K (Get-Content "C:\Users\Ronin\aes_key_decrypted.hex") -iv (Get-Content "C:\Users\Ronin\iv.hex")`

---

## Step 8 – Verify File Integrity Using SHA-256

- **Original File Hash:** `openssl dgst -sha256 alice_message.txt > original_sha256.txt`  
- **Decrypted File Hash:** `openssl dgst -sha256 decrypted_message.txt > decrypted_sha256.txt`  
- **Compare Hashes:** `fc original_sha256.txt decrypted_sha256.txt`

---

## AES vs RSA Comparison

- **Type:** AES-256 is symmetric (same key for encryption and decryption); RSA-2048 is asymmetric (public/private key pair)  
- **Speed:** AES is fast and ideal for large files; RSA is slow and unsuitable for bulk data  
- **Security:** AES is powerful if the key remains secret; RSA is strong for secure key exchange or small data  
- **Use Case:** AES encrypts the actual message or file; RSA is mainly used to securely transmit AES keys  
- **Key Size:** AES uses 256-bit keys; RSA uses 2048-bit keys  
- **Encryption/Decryption:** AES uses the same key for both; RSA uses different keys for encryption and decryption

---

## Artifacts

- `alice_message.txt`  
- `encrypted_file.bin`  
- `aes_key_encrypted.bin`  
- `decrypted_message.txt`  
- `public.pem`  
- `private.pem`  
- `original_sha256.txt`  
- `decrypted_sha256.txt`
- `Task2.md`