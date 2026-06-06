#!/usr/bin/env python3
"""
enhanced_zwc_stego.py
=====================
ENHANCED Zero-Width Character (ZWC) Text Steganography
Defense Group - WQE7003 Group Assignment

Enhancement over baseline (Bashir et al., 2020):
  1. AES-256-CBC Encryption of secret message before embedding
  2. ZWC Symbol Permutation (4 ZWC chars mapped by key-derived shuffle)
  3. Randomized insertion positions (key-seeded PRNG selects word positions)
  4. HMAC-SHA256 integrity tag appended to payload

The 4 ZWC symbols used (mapped per permutation key):
  U+200B  Zero Width Space
  U+200C  Zero Width Non-Joiner
  U+FEFF  Zero Width No-Break Space (BOM)
  U+2060  Word Joiner

With 4 symbols, each ZWC encodes 2 bits -> 2x capacity vs original.

Usage:
  python3 enhanced_zwc_stego.py embed   --cover cover.txt --secret "Hello" --passkey "MyKey123!" --output stego_enhanced.txt
  python3 enhanced_zwc_stego.py extract --stego stego_enhanced.txt --passkey "MyKey123!"
"""

import argparse
import sys
import os
import hashlib
import hmac
import struct
import random
import base64

# ──────────────────────────────────────────────────────────────────
# AES-256-CBC (pure Python, no external libs needed)
# Uses Python's built-in hashlib + manual PKCS7 + CBC mode via PyCryptodome
# We use a safe import with fallback guidance
# ──────────────────────────────────────────────────────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

# 4 ZWC symbols (2-bit encoding)
ZWC_SYMBOLS = [
    '\u200B',   # 00
    '\u200C',   # 01
    '\uFEFF',   # 10
    '\u2060',   # 11
]

PAYLOAD_TERMINATOR = b'\xDE\xAD\xBE\xEF'  # 4-byte end marker

def derive_key_iv(passkey: str) -> tuple:
    """Derive AES-256 key (32 bytes) and IV (16 bytes) from passkey via SHA-512."""
    digest = hashlib.sha512(passkey.encode('utf-8')).digest()
    key = digest[:32]
    iv  = digest[32:48]
    return key, iv

def derive_permutation(passkey: str) -> list:
    """Derive ZWC symbol permutation order from passkey using SHA-256 seed."""
    seed = int(hashlib.sha256(('perm:' + passkey).encode()).hexdigest(), 16)
    rng = random.Random(seed)
    perm = list(range(4))
    rng.shuffle(perm)
    return perm

def derive_positions(passkey: str, cover_words: int, n_chunks: int) -> list:
    """Derive pseudo-random word positions to insert ZWC chunks into."""
    seed = int(hashlib.sha256(('pos:' + passkey).encode()).hexdigest(), 16)
    rng = random.Random(seed)
    available = list(range(cover_words - 1))
    if n_chunks > len(available):
        return sorted(available)  # saturate cover
    positions = sorted(rng.sample(available, n_chunks))
    return positions

def text_to_dibits(data: bytes, perm: list) -> str:
    """Convert bytes to ZWC string using 2-bit (dibit) encoding + permutation."""
    zwc_str = ''
    for byte in data:
        for shift in (6, 4, 2, 0):
            dibit = (byte >> shift) & 0b11
            mapped = perm[dibit]
            zwc_str += ZWC_SYMBOLS[mapped]
    return zwc_str

def dibits_to_bytes(zwc_str: str, perm: list) -> bytes:
    """Convert ZWC string back to bytes."""
    # Build inverse permutation
    inv_perm = [0] * 4
    for i, p in enumerate(perm):
        inv_perm[p] = i

    result = []
    nibbles = []
    for ch in zwc_str:
        if ch in ZWC_SYMBOLS:
            mapped_idx = ZWC_SYMBOLS.index(ch)
            original_dibit = inv_perm[mapped_idx]
            nibbles.append(original_dibit)

    for i in range(0, len(nibbles) - 3, 4):
        byte_val = (nibbles[i] << 6) | (nibbles[i+1] << 4) | (nibbles[i+2] << 2) | nibbles[i+3]
        result.append(byte_val)
    return bytes(result)

def encrypt_message(message: str, passkey: str) -> bytes:
    """AES-256-CBC encrypt message. Falls back to XOR if PyCryptodome unavailable."""
    plaintext = message.encode('utf-8')
    if AES_AVAILABLE:
        key, iv = derive_key_iv(passkey)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return ciphertext
    else:
        # XOR cipher fallback (weaker but dependency-free)
        key_bytes = hashlib.sha256(passkey.encode()).digest() * ((len(plaintext) // 32) + 1)
        xored = bytes(a ^ b for a, b in zip(plaintext, key_bytes[:len(plaintext)]))
        print("[WARN] PyCryptodome not installed. Using XOR fallback. Install via: pip install pycryptodome")
        return xored

def decrypt_message(ciphertext: bytes, passkey: str) -> str:
    """AES-256-CBC decrypt ciphertext."""
    if AES_AVAILABLE:
        key, iv = derive_key_iv(passkey)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode('utf-8', errors='replace')
        except Exception:
            return '<Decryption failed — wrong passkey or corrupted data>'
    else:
        key_bytes = hashlib.sha256(passkey.encode()).digest() * ((len(ciphertext) // 32) + 1)
        xored = bytes(a ^ b for a, b in zip(ciphertext, key_bytes[:len(ciphertext)]))
        return xored.decode('utf-8', errors='replace')

def compute_hmac(data: bytes, passkey: str) -> bytes:
    """Compute HMAC-SHA256 of data."""
    key = hashlib.sha256(('hmac:' + passkey).encode()).digest()
    return hmac.new(key, data, hashlib.sha256).digest()

def embed(cover_text: str, secret_message: str, passkey: str) -> str:
    """Embed secret message into cover text with encryption + permutation."""
    # Step 1: Encrypt message
    ciphertext = encrypt_message(secret_message, passkey)
    
    # Step 2: Append HMAC tag for integrity verification
    tag = compute_hmac(ciphertext, passkey)
    
    # Step 3: Build payload = [4-byte length][ciphertext][32-byte HMAC][terminator]
    length_header = struct.pack('>I', len(ciphertext))
    payload = length_header + ciphertext + tag + PAYLOAD_TERMINATOR

    # Step 4: Get permutation key
    perm = derive_permutation(passkey)

    # Step 5: Convert payload to ZWC string (2 bits per ZWC)
    zwc_payload = text_to_dibits(payload, perm)
    n_zwc = len(zwc_payload)

    # Step 6: Determine insertion positions
    words = cover_text.split(' ')
    if n_zwc > len(words) - 1:
        print(f"[WARNING] Cover text too short! Need {n_zwc} word-gaps, have {len(words)-1}.")
        print(f"          Try a longer cover text.")

    positions = derive_positions(passkey, len(words), n_zwc)
    
    # Step 7: Insert ZWC chars at derived positions
    result_parts = list(words)  # copy
    inserted = 0
    for pos in positions:
        if inserted >= n_zwc:
            break
        # Insert one ZWC char at this word position (after word[pos], before space)
        result_parts[pos] = result_parts[pos] + zwc_payload[inserted]
        inserted += 1

    stego_text = ' '.join(result_parts)
    
    print(f"[INFO] Encryption: {'AES-256-CBC' if AES_AVAILABLE else 'XOR-fallback'}")
    print(f"[INFO] Passkey-derived permutation: {perm}")
    print(f"[INFO] Payload: {len(payload)} bytes -> {n_zwc} ZWC characters (2 bits/char)")
    print(f"[INFO] Inserted {inserted}/{n_zwc} ZWC characters at {inserted} random positions.")
    print(f"[INFO] Stego text saved. Visual appearance identical to cover text.")
    return stego_text

def extract(stego_text: str, passkey: str) -> str:
    """Extract and decrypt hidden message from stego text."""
    perm = derive_permutation(passkey)

    # Collect all ZWC chars (in order of appearance)
    zwc_collected = ''.join(ch for ch in stego_text if ch in ZWC_SYMBOLS)

    if not zwc_collected:
        return '[ERROR] No ZWC characters found in text.'

    # Decode to bytes
    raw_bytes = dibits_to_bytes(zwc_collected, perm)

    if len(raw_bytes) < 4:
        return '[ERROR] Payload too short.'

    # Parse payload
    try:
        ct_length = struct.unpack('>I', raw_bytes[:4])[0]
        ciphertext = raw_bytes[4:4 + ct_length]
        tag_start = 4 + ct_length
        stored_tag = raw_bytes[tag_start:tag_start + 32]
        
        # Verify HMAC
        expected_tag = compute_hmac(ciphertext, passkey)
        if not hmac.compare_digest(stored_tag, expected_tag):
            return '[ERROR] HMAC verification FAILED. Data may be tampered or wrong passkey.'
        
        print('[INFO] HMAC integrity check: PASSED')
        
        # Decrypt
        message = decrypt_message(ciphertext, passkey)
        return message

    except Exception as e:
        return f'[ERROR] Extraction failed: {e}'

def main():
    parser = argparse.ArgumentParser(description='Enhanced ZWC Text Steganography (AES + Permutation)')
    subparsers = parser.add_subparsers(dest='command')

    embed_parser = subparsers.add_parser('embed', help='Embed encrypted secret message into cover text')
    embed_parser.add_argument('--cover',    required=True, help='Path to cover text file')
    embed_parser.add_argument('--secret',   required=True, help='Secret message to embed')
    embed_parser.add_argument('--passkey',  required=True, help='Passkey for encryption & permutation')
    embed_parser.add_argument('--output',   required=True, help='Output stego text file path')

    extract_parser = subparsers.add_parser('extract', help='Extract and decrypt hidden message')
    extract_parser.add_argument('--stego',   required=True, help='Path to stego text file')
    extract_parser.add_argument('--passkey', required=True, help='Passkey for decryption')

    args = parser.parse_args()

    if args.command == 'embed':
        if not os.path.exists(args.cover):
            print(f"[ERROR] Cover file not found: {args.cover}")
            sys.exit(1)
        with open(args.cover, 'r', encoding='utf-8') as f:
            cover = f.read()
        stego = embed(cover, args.secret, args.passkey)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(stego)
        print(f"[INFO] Output: {args.output}")

    elif args.command == 'extract':
        if not os.path.exists(args.stego):
            print(f"[ERROR] Stego file not found: {args.stego}")
            sys.exit(1)
        with open(args.stego, 'r', encoding='utf-8') as f:
            stego = f.read()
        msg = extract(stego, args.passkey)
        print(f"[RESULT] Extracted message: {msg}")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
