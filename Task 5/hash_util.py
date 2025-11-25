import hashlib
import json

def compute_hashes(filename):
    data = open(filename, "rb").read()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest()
    }

def store_hashes(file, hashes):
    with open("hashes.json", "w") as f:
        json.dump({file: hashes}, f, indent=4)

def verify_integrity(original, modified):
    orig = compute_hashes(original)
    mod = compute_hashes(modified)
    print("Integrity:", "PASS" if orig == mod else "FAIL")

if __name__ == "__main__":
    hashes = compute_hashes("original.txt")
    store_hashes("original.txt", hashes)
    verify_integrity("original.txt", "tampered.txt")
