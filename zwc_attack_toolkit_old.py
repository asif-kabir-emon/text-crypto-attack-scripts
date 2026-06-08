#!/usr/bin/env python3
"""
zwc_attack_toolkit.py
=====================
ATTACK GROUP - WQE7003 Group Assignment
ZWC Steganography Attack Toolkit

Implements both PASSIVE and ACTIVE attacks against ZWC text steganography.

PASSIVE ATTACKS (detection / analysis — no modification):
  1. ZWC Scanner          — Detect presence of ZWC characters
  2. Statistical Analysis — Frequency/entropy of ZWC patterns
  3. Binary Extraction    — Extract raw bit sequences
  4. Known-key Decoder    — If passkey is known, decode payload

ACTIVE ATTACKS (modification — destroy or alter the hidden message):
  5. ZWC Strip Attack     — Remove all ZWC characters (destroys message)
  6. ZWC Noise Attack     — Inject random ZWC chars (corrupts message)
  7. ZWC Substitution     — Replace ZWC chars with different symbols
  8. HMAC Brute-Force     — Try common passkeys to verify HMAC integrity
  9. Permutation Brute-Force — Try known passkeys for enhanced version

Usage:
  python3 zwc_attack_toolkit.py scan      --file stego.txt
  python3 zwc_attack_toolkit.py stats     --file stego.txt
  python3 zwc_attack_toolkit.py extract   --file stego.txt
  python3 zwc_attack_toolkit.py strip     --file stego.txt  --output clean.txt
  python3 zwc_attack_toolkit.py noise     --file stego.txt  --output noisy.txt  --density 0.5
  python3 zwc_attack_toolkit.py brute     --file stego.txt  --wordlist wordlist.txt
  python3 zwc_attack_toolkit.py fullscan  --file stego.txt
"""

import argparse
import sys
import os
import random
import hashlib
import hmac as hmac_lib
import struct
import json
from collections import Counter

# ──────────────────────────────────────────────────────────────────
# ZWC character definitions
# ──────────────────────────────────────────────────────────────────
ZWC_MAP = {
    '\u200B': 'ZWSP  (U+200B) Zero Width Space',
    '\u200C': 'ZWNJ  (U+200C) Zero Width Non-Joiner',
    '\u200D': 'ZWJ   (U+200D) Zero Width Joiner',
    '\uFEFF': 'ZWNBS (U+FEFF) Zero Width No-Break Space / BOM',
    '\u2060': 'WJ    (U+2060) Word Joiner',
    '\u2061': 'FA    (U+2061) Function Application',
    '\u2062': 'IT    (U+2062) Invisible Times',
    '\u2063': 'IS    (U+2063) Invisible Separator',
    '\u2064': 'IP    (U+2064) Invisible Plus',
}
ZWC_CHARS = set(ZWC_MAP.keys())

# Symbols used by baseline (1-bit encoding)
ORIG_ZWC_0 = '\u200B'
ORIG_ZWC_1 = '\u200C'

# Symbols used by enhanced (2-bit encoding)
ENH_ZWC_SYMBOLS = ['\u200B', '\u200C', '\uFEFF', '\u2060']

PAYLOAD_TERMINATOR = b'\xDE\xAD\xBE\xEF'

# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────
def load_file(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def save_file(path: str, content: str):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[INFO] Output saved: {path}")

def banner(title: str):
    print('\n' + '='*60)
    print(f"  {title}")
    print('='*60)

# ──────────────────────────────────────────────────────────────────
# PASSIVE ATTACK 1: ZWC Scanner
# ──────────────────────────────────────────────────────────────────
def attack_scan(text: str):
    banner("PASSIVE ATTACK 1 — ZWC Scanner")
    found = {}
    for ch, name in ZWC_MAP.items():
        count = text.count(ch)
        if count > 0:
            found[ch] = (name, count)
    
    total_chars = len(text)
    zwc_total = sum(c for _, c in found.values())
    visible_chars = total_chars - zwc_total

    print(f"File total characters  : {total_chars}")
    print(f"Visible characters     : {visible_chars}")
    print(f"ZWC characters found   : {zwc_total}")
    print(f"ZWC-to-visible ratio   : {zwc_total/visible_chars:.4f}" if visible_chars else "N/A")
    print()

    if found:
        print("ZWC Characters Detected:")
        for ch, (name, count) in found.items():
            print(f"  [{hex(ord(ch))}] {name:45s} -> {count} occurrences")
        print()
        print("[VERDICT] Steganographic content LIKELY PRESENT.")
        print("[REASON]  Zero-width characters have no legitimate display purpose in plain text.")
    else:
        print("[VERDICT] No ZWC characters detected. Text appears clean.")
    
    return bool(found)

# ──────────────────────────────────────────────────────────────────
# PASSIVE ATTACK 2: Statistical Analysis
# ──────────────────────────────────────────────────────────────────
def attack_stats(text: str):
    banner("PASSIVE ATTACK 2 — Statistical Analysis")
    
    zwc_sequence = [ch for ch in text if ch in ZWC_CHARS]
    
    if not zwc_sequence:
        print("[RESULT] No ZWC characters to analyze.")
        return
    
    print(f"Total ZWC characters : {len(zwc_sequence)}")
    
    # Frequency
    freq = Counter(zwc_sequence)
    print("\nFrequency Distribution:")
    for ch, cnt in freq.most_common():
        pct = cnt/len(zwc_sequence)*100
        bar = '█' * int(pct/2)
        print(f"  U+{ord(ch):04X}  {bar:25s} {cnt:5d} ({pct:.1f}%)")
    
    # Estimate encoding
    n_distinct = len(freq)
    print(f"\nDistinct ZWC types used : {n_distinct}")
    if n_distinct == 2:
        print("[INFERENCE] Likely 1-bit encoding (2 symbols -> binary 0/1)")
        print("            Consistent with baseline technique (Bashir et al., 2020)")
        # Estimate payload size
        bits = len(zwc_sequence)
        print(f"[INFERENCE] Estimated raw payload : ~{bits} bits = ~{bits//8} bytes")
    elif n_distinct == 4:
        print("[INFERENCE] Likely 2-bit (dibit) encoding (4 symbols -> 00/01/10/11)")
        print("            Consistent with enhanced technique")
        bits = len(zwc_sequence) * 2
        print(f"[INFERENCE] Estimated raw payload : ~{bits} bits = ~{bits//8} bytes")
    
    # Position analysis
    positions = [i for i, ch in enumerate(text) if ch in ZWC_CHARS]
    if len(positions) > 1:
        gaps = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
        avg_gap = sum(gaps)/len(gaps)
        print(f"\nPosition Analysis:")
        print(f"  First ZWC at position : {positions[0]}")
        print(f"  Last ZWC at position  : {positions[-1]}")
        print(f"  Average gap between ZWCs : {avg_gap:.1f} characters")
        if avg_gap > 5:
            print("  [INFERENCE] Sparse insertion - consistent with word-boundary placement")
        else:
            print("  [INFERENCE] Dense insertion - possibly block embedding")

# ──────────────────────────────────────────────────────────────────
# PASSIVE ATTACK 3: Raw Bit Extraction (original technique)
# ──────────────────────────────────────────────────────────────────
def attack_extract_raw(text: str):
    banner("PASSIVE ATTACK 3 — Raw Bit Extraction (Original Technique Assumed)")
    
    zwc_seq = [ch for ch in text if ch in (ORIG_ZWC_0, ORIG_ZWC_1)]
    
    if not zwc_seq:
        print("[INFO] No U+200B/U+200C characters found (original technique symbols).")
        return
    
    bits = ''.join('0' if ch == ORIG_ZWC_0 else '1' for ch in zwc_seq)
    print(f"Extracted {len(bits)} bits from ZWC chars.")
    print(f"First 64 bits: {bits[:64]}")
    
    # Try to decode as UTF-8, stopping at sentinel 0xFF
    message_bytes = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = int(bits[i:i+8], 2)
        if byte_val == 0xFF:
            break
        message_bytes.append(byte_val)
    
    try:
        raw_msg = bytes(message_bytes).decode('utf-8', errors='replace')
        print(f"\n[RESULT] Decoded message (no encryption assumed): '{raw_msg}'")
        print("[VERDICT] Original (unencrypted) technique: message RECOVERED successfully.")
    except Exception as e:
        print(f"[RESULT] Could not decode as UTF-8: {e}")

# ──────────────────────────────────────────────────────────────────
# PASSIVE ATTACK 4: Known-Key Decoder (enhanced technique)
# ──────────────────────────────────────────────────────────────────
def decode_enhanced_with_key(text: str, passkey: str) -> str:
    """Try to decode enhanced stego text with a given passkey."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        AES_AVAIL = True
    except ImportError:
        AES_AVAIL = False

    def derive_perm(pk):
        import random as rnd
        seed = int(hashlib.sha256(('perm:'+pk).encode()).hexdigest(), 16)
        r = rnd.Random(seed)
        p = list(range(4))
        r.shuffle(p)
        return p

    perm = derive_perm(passkey)
    inv_perm = [0]*4
    for i, p in enumerate(perm):
        inv_perm[p] = i

    zwc_seq = [ch for ch in text if ch in ENH_ZWC_SYMBOLS]
    if not zwc_seq:
        return '[ERROR] No enhanced ZWC chars found.'

    nibbles = []
    for ch in zwc_seq:
        idx = ENH_ZWC_SYMBOLS.index(ch)
        nibbles.append(inv_perm[idx])
    
    raw = []
    for i in range(0, len(nibbles)-3, 4):
        b = (nibbles[i]<<6)|(nibbles[i+1]<<4)|(nibbles[i+2]<<2)|nibbles[i+3]
        raw.append(b)
    raw = bytes(raw)

    if len(raw) < 4:
        return '[ERROR] Payload too short.'

    ct_len = struct.unpack('>I', raw[:4])[0]
    ciphertext = raw[4:4+ct_len]
    stored_tag = raw[4+ct_len:4+ct_len+32]
    
    # HMAC check
    hmac_key = hashlib.sha256(('hmac:'+passkey).encode()).digest()
    expected = hmac_lib.new(hmac_key, ciphertext, hashlib.sha256).digest()
    
    if not hmac_lib.compare_digest(stored_tag, expected):
        return '[FAIL] HMAC mismatch — wrong passkey.'
    
    # Decrypt
    digest = hashlib.sha512(passkey.encode()).digest()
    key, iv = digest[:32], digest[32:48]
    
    if AES_AVAIL:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), 16)
            return plaintext.decode('utf-8', errors='replace')
        except Exception:
            return '[FAIL] AES decryption error.'
    else:
        kb = hashlib.sha256(passkey.encode()).digest() * ((len(ciphertext)//32)+1)
        return bytes(a^b for a,b in zip(ciphertext, kb[:len(ciphertext)])).decode('utf-8', errors='replace')

# ──────────────────────────────────────────────────────────────────
# ACTIVE ATTACK 5: ZWC Strip Attack
# ──────────────────────────────────────────────────────────────────
def attack_strip(text: str) -> str:
    banner("ACTIVE ATTACK 5 — ZWC Strip Attack")
    stripped = ''.join(ch for ch in text if ch not in ZWC_CHARS)
    original_len = len(text)
    removed = original_len - len(stripped)
    print(f"Original length  : {original_len} chars")
    print(f"ZWC chars removed: {removed}")
    print(f"Clean length     : {len(stripped)} chars")
    print("[RESULT] All hidden ZWC data DESTROYED. Receiver cannot recover message.")
    return stripped

# ──────────────────────────────────────────────────────────────────
# ACTIVE ATTACK 6: ZWC Noise Injection Attack
# ──────────────────────────────────────────────────────────────────
def attack_noise(text: str, density: float = 0.3, seed: int = 42) -> str:
    banner("ACTIVE ATTACK 6 — ZWC Noise Injection Attack")
    rng = random.Random(seed)
    noise_symbols = list(ZWC_CHARS)
    
    chars = list(text)
    injected = 0
    result = []
    for ch in chars:
        result.append(ch)
        if ch == ' ' and rng.random() < density:
            result.append(rng.choice(noise_symbols))
            injected += 1
    
    noisy = ''.join(result)
    print(f"Original ZWC count : {sum(1 for c in text if c in ZWC_CHARS)}")
    print(f"Noise ZWC injected : {injected}")
    print(f"Total ZWC now      : {sum(1 for c in noisy if c in ZWC_CHARS)}")
    print("[RESULT] Noise injected. Original message bits corrupted.")
    print("[RESULT] Extraction will produce garbled output. HMAC will FAIL on enhanced version.")
    return noisy

# ──────────────────────────────────────────────────────────────────
# ACTIVE ATTACK 7: ZWC Substitution Attack
# ──────────────────────────────────────────────────────────────────
def attack_substitute(text: str) -> str:
    banner("ACTIVE ATTACK 7 — ZWC Substitution Attack")
    ORIG_SYMBOLS = {'\u200B', '\u200C'}
    substituted = 0
    result = []
    for ch in text:
        if ch in ORIG_SYMBOLS:
            # Replace with a different ZWC (flips bits)
            result.append('\u2060')  # Word Joiner (not in original mapping)
            substituted += 1
        else:
            result.append(ch)
    print(f"ZWC chars substituted: {substituted}")
    print("[RESULT] Bit values altered. Extraction will decode garbage.")
    return ''.join(result)

# ──────────────────────────────────────────────────────────────────
# ACTIVE ATTACK 8/9: Passkey Brute-Force
# ──────────────────────────────────────────────────────────────────
def attack_brute(text: str, wordlist_path: str):
    banner("ACTIVE ATTACK 8/9 — Passkey Brute-Force")
    
    if not os.path.exists(wordlist_path):
        # Built-in test wordlist
        candidates = [
            'password', '123456', 'secret', 'admin', 'letmein',
            'qwerty', 'monkey', 'dragon', 'master', 'hello',
            'MyKey123!', 'StegKey', 'hidden', 'covert', 'crypto',
            'defend', 'attack', 'stego', 'unicode', 'zwc2024',
            'abc123', 'passkey', 'test', 'pass', 'key',
        ]
        print(f"[INFO] Wordlist not found. Using built-in {len(candidates)}-word test list.")
    else:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            candidates = [line.strip() for line in f if line.strip()]
        print(f"[INFO] Loaded {len(candidates)} candidates from {wordlist_path}")
    
    print(f"[INFO] Attempting brute-force on enhanced ZWC stego text...\n")
    
    found = False
    for i, key in enumerate(candidates):
        result = decode_enhanced_with_key(text, key)
        if not result.startswith('[FAIL]') and not result.startswith('[ERROR]'):
            print(f"[!!] PASSKEY FOUND: '{key}'")
            print(f"[!!] Decoded message: {result}")
            found = True
            break
        if i % 10 == 0:
            print(f"     Tried {i+1}/{len(candidates)} keys...", end='\r')
    
    if not found:
        print(f"\n[RESULT] Passkey NOT found in wordlist ({len(candidates)} attempts).")
        print("[RESULT] AES-256 + HMAC resists dictionary attacks. Full brute-force is infeasible.")

# ──────────────────────────────────────────────────────────────────
# COMPREHENSIVE FULL SCAN
# ──────────────────────────────────────────────────────────────────
def attack_fullscan(text: str):
    """Run all passive attacks and produce a comprehensive report."""
    banner("COMPREHENSIVE FULL SCAN — All Passive Attacks")
    present = attack_scan(text)
    if present:
        attack_stats(text)
        attack_extract_raw(text)
    else:
        print("[INFO] No hidden content detected. Skipping further analysis.")

# ──────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='ZWC Steganography Attack Toolkit')
    sub = parser.add_subparsers(dest='cmd')

    def add_file(p): p.add_argument('--file', required=True, help='Input text file')
    def add_out(p):  p.add_argument('--output', required=True, help='Output text file')

    p_scan  = sub.add_parser('scan',    help='Detect ZWC characters')
    p_stats = sub.add_parser('stats',   help='Statistical analysis')
    p_ext   = sub.add_parser('extract', help='Raw bit extraction')
    p_strip = sub.add_parser('strip',   help='Strip all ZWC chars')
    p_noise = sub.add_parser('noise',   help='Inject random ZWC noise')
    p_sub   = sub.add_parser('subst',   help='ZWC substitution attack')
    p_brute = sub.add_parser('brute',   help='Passkey brute-force')
    p_full  = sub.add_parser('fullscan',help='Run all passive attacks')
    p_known = sub.add_parser('decode',  help='Decode with known passkey')

    for p in [p_scan, p_stats, p_ext, p_strip, p_noise, p_sub, p_brute, p_full, p_known]:
        add_file(p)

    add_out(p_strip)
    add_out(p_noise)
    add_out(p_sub)
    p_noise.add_argument('--density', type=float, default=0.3, help='Noise density 0.0-1.0')
    p_brute.add_argument('--wordlist', default='wordlist.txt', help='Passkey wordlist file')
    p_known.add_argument('--passkey', required=True, help='Known passkey to try')

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    text = load_file(args.file)

    if   args.cmd == 'scan':     attack_scan(text)
    elif args.cmd == 'stats':    attack_stats(text)
    elif args.cmd == 'extract':  attack_extract_raw(text)
    elif args.cmd == 'fullscan': attack_fullscan(text)
    elif args.cmd == 'strip':
        clean = attack_strip(text)
        save_file(args.output, clean)
    elif args.cmd == 'noise':
        noisy = attack_noise(text, args.density)
        save_file(args.output, noisy)
    elif args.cmd == 'subst':
        subst = attack_substitute(text)
        save_file(args.output, subst)
    elif args.cmd == 'brute':
        attack_brute(text, args.wordlist)
    elif args.cmd == 'decode':
        result = decode_enhanced_with_key(text, args.passkey)
        print(f"\n[RESULT] {result}")

if __name__ == '__main__':
    main()
