#!/usr/bin/env python3
from binascii import unhexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
KEY = b"this_is_16_bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def padding_oracle(ciphertext: bytes) -> bool:
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    block_len = BLOCK_SIZE
    intermediate = [0] * block_len
    plaintext = [0] * block_len
    for pad_len in range(1, block_len + 1):
        i = block_len - pad_len
        found = False
        for guess in range(256):
            forged = bytearray(block_len)
            for j in range(i + 1, block_len):
                forged[j] = intermediate[j] ^ pad_len
            forged[i] = guess
            test_ct = bytes(forged) + target_block
            if padding_oracle(test_ct):
                intermediate[i] = guess ^ pad_len
                plaintext[i] = intermediate[i] ^ prev_block[i]
                found = True
                break
        if not found:
            raise RuntimeError(f"Failed to find a valid byte at position {i}")
    return bytes(plaintext)

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    if len(blocks) < 2:
        raise ValueError("Ciphertext must contain at least IV + 1 block")
    plaintext = bytearray()
    for i in range(1, len(blocks)):
        prev_block = blocks[i - 1]
        target_block = blocks[i]
        pt_block = decrypt_block(prev_block, target_block)
        plaintext.extend(pt_block)
    return bytes(plaintext)

def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
    except Exception as e:
        return f"[!] Error during unpad/decode: {e}"
    try:
        return unpadded.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[!] Decode error: {e}"

if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f" Recovered plaintext (raw bytes): {recovered}")
        print(f" Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\n Final plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n Error occurred: {e}")
