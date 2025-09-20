#!/usr/bin/env python3
import hashlib
import sys

# ----------------- User Config -----------------
# Fill these to match the hash algorithms of your four hashes (The order here MUST match the order of hashes in your andrewID_hashes.txt file.)

HASH_ALGO_1 = "MD5"   # <-- Fill in the algorithm for hash 1 (e.g., "sha512")
HASH_ALGO_2 = "SHA1"   # <-- Fill in the algorithm for hash 2 (e.g., "md5")
HASH_ALGO_3 = "SHA256"   # <-- Fill in the algorithm for hash 3 (e.g., "Tiger")
HASH_ALGO_4 = "SHA512"   # <-- Fill in the algorithm for hash 4 (e.g., "sha256") 
# ------------------------------------------------

def hash_password(password, algo):
    """Return the hash of the password using the given algorithm."""
    h = hashlib.new(algo)
    h.update(password.encode())
    return h.hexdigest()

def load_hashes(filename):
    """Read hashes from file, expecting 4 lines like 'hash 1 : ...'"""
    hashes = []
    with open(filename, "r") as f:
        for line in f:
            if ":" in line:
                hashes.append(line.split(":")[1].strip())
    if len(hashes) != 4:
        print("Expecting exactly 4 hashes in the file!")
        exit(1)
    return hashes

def load_wordlist(filename):
    """Load passwords from wordlist."""
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def crack_hash(target_hash, wordlist, algo):
    """Try to find a password in wordlist that matches the target_hash."""
    for pw in wordlist:
        if hash_password(pw, algo) == target_hash:
            return pw
    return None

def main():
    if len(sys.argv) != 3:
        # print(sys.argv[0])
        print(f"Usage: {sys.argv[0]} <hashes.txt> <wordlist.txt>")
        exit(1)

    hashes_file = sys.argv[1]
    wordlist_file = sys.argv[2]

    hashes = load_hashes(hashes_file)
    wordlist = load_wordlist(wordlist_file)

    algos = [HASH_ALGO_1, HASH_ALGO_2, HASH_ALGO_3, HASH_ALGO_4]

    for i, h in enumerate(hashes):
        pw = crack_hash(h, wordlist, algos[i])
        if pw:
            print(f"Password: {pw}\n{algos[i].upper()}: {h}")
        else:
            print(f"Password: \n{algos[i].upper()}: {h} impossible")
        print("-" * 50)

if __name__ == "__main__":
    main()
