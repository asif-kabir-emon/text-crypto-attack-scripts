#!/usr/bin/env python3
"""
zwc_attack_toolkit.py
=====================
ATTACK GROUP - WQE7003 Group Assignment
ZWC Steganography Attack Toolkit

Implements both PASSIVE and ACTIVE adaptive blind attacks against ZWC text steganography.

PASSIVE ATTACKS (detection / analysis — no modification):
  1. ZWC Scanner          — Detect presence of ZWC characters
  2. Statistical Analysis — Dynamic frequency/entropy analysis of ZWC patterns
  3. Blind Extraction     — Dynamically adapt and extract raw bit sequences
  4. Known-key Decoder    — Adaptive multi-bit decode via known passkey

ACTIVE ATTACKS (modification — destroy or alter the hidden message):
  5. ZWC Strip Attack     — Remove all ZWC characters (destroys message)
  6. ZWC Noise Attack     — Inject random ZWC chars (corrupts message)
  7. Blind Substitution   — Dynamically replace active ZWC chars to scramble layout
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

    # Directional formatting characters
    '\u200E': 'LRM   (U+200E) Left-to-Right Mark',
    '\u200F': 'RLM   (U+200F) Right-to-Left Mark',

    '\u202A': 'LRE   (U+202A) Left-to-Right Embedding',
    '\u202B': 'RLE   (U+202B) Right-to-Left Embedding',
    '\u202C': 'PDF   (U+202C) Pop Directional Formatting',
    '\u202D': 'LRO   (U+202D) Left-to-Right Override',
    '\u202E': 'RLO   (U+202E) Right-to-Left Override',

    '\u2066': 'LRI   (U+2066) Left-to-Right Isolate',
    '\u2067': 'RLI   (U+2067) Right-to-Left Isolate',
    '\u2068': 'FSI   (U+2068) First Strong Isolate',
    '\u2069': 'PDI   (U+2069) Pop Directional Isolate',

    # Mongolian invisible separator
    '\u180E': 'MVS   (U+180E) Mongolian Vowel Separator',

    # Soft hyphen (often invisible)
    '\u00AD': 'SHY   (U+00AD) Soft Hyphen',

    # Combining Grapheme Joiner
    '\u034F': 'CGJ   (U+034F) Combining Grapheme Joiner',
}
ZWC_CHARS = set(ZWC_MAP.keys())

# Default fallback symbols for 1-bit encoding (used if blind detection finds < 2 distinct ZWCs)
ORIG_ZWC_0 = '\u200B'
ORIG_ZWC_1 = '\u200C'

# Default fallback symbols for 2-bit encoding (used if blind detection finds < 4 distinct ZWCs)
ENH_ZWC_SYMBOLS = ['\u200B', '\u200C', '\uFEFF', '\u2060']

# Unused placeholder terminator (retained for baseline structure compatibility)
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
    print('\n' + '=' * 60)
    print(f"  {title}")
    print('=' * 60)


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
    print(f"ZWC-to-visible ratio   : {zwc_total / visible_chars:.4f}" if visible_chars else "N/A")
    print()

    if found:
        print("ZWC Characters Detected:")
        for ch, (name, count) in found.items():
            # Dynamic visual bar for each ZWC type (percentage of total ZWCs)
            pct = (count / zwc_total) * 100 if zwc_total else 0
            bar = '█' * int(pct / 2)
            print(f"  [{hex(ord(ch))}] {name:45s} -> {count:5d} occurrences {bar} ({pct:.1f}%)")
        print()
        print("[VERDICT] Steganographic content LIKELY PRESENT.")
        print("[REASON]  Zero-width characters have no legitimate display purpose in plain text.")
        # Dynamic suggestion based on distinct symbol count
        distinct = len(found)
        if distinct == 2:
            print("[ADVICE]  Only 2 distinct ZWC types → likely 1‑bit encoding. Use 'extract' for blind recovery.")
        elif distinct == 4:
            print("[ADVICE]  Exactly 4 distinct ZWC types → possible 2‑bit encoding. Use 'brute' with a passkey wordlist.")
        elif distinct > 4:
            print("[ADVICE]  Many ZWC types → custom or multi‑layer steganography. Passive analysis may be limited.")
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
        pct = cnt / len(zwc_sequence) * 100
        bar = '█' * int(pct / 2)
        print(f"  U+{ord(ch):04X}  {bar:25s} {cnt:5d} ({pct:.1f}%)")

    # Dynamic encoding inference with entropy estimation
    n_distinct = len(freq)
    print(f"\nDistinct ZWC types used : {n_distinct}")
    if n_distinct == 2:
        print("[INFERENCE] Likely 1-bit encoding (2 symbols -> binary 0/1)")
        print("            Adaptive blind attack can crack this layout automatically.")
        bits = len(zwc_sequence)
        print(f"[INFERENCE] Estimated raw payload : ~{bits} bits = ~{bits // 8} bytes")

        # Uniformity check (for true 1-bit encoding, both symbols should appear roughly equally)
        counts = list(freq.values())
        if len(counts) == 2 and max(counts) / min(counts) > 3:
            print("[WARNING]  Frequency imbalance between the two ZWC types. Possibly not pure 1‑bit encoding or unbalanced message.")
    elif n_distinct == 4:
        print("[INFERENCE] Likely 2-bit (dibit) encoding (4 symbols -> 00/01/10/11)")
        print("            Custom symbol mapping detected. Passkey brute-force required.")
        bits = len(zwc_sequence) * 2
        print(f"[INFERENCE] Estimated raw payload : ~{bits} bits = ~{bits // 8} bytes")
        # Check uniformity
        counts = list(freq.values())
        avg = sum(counts) / 4
        max_dev = max(abs(c - avg) for c in counts) / avg if avg > 0 else 0
        if max_dev > 0.5:
            print("[WARNING]  Uneven distribution of the 4 ZWC types. Possibly not pure 2‑bit encoding or payload is not random.")
    else:
        print(f"[INFERENCE] Complex multi-symbol layout ({n_distinct} types).")
        print("            Possibly customized n-bit encoding or layered steganography.")
        # Attempt to guess bits per symbol: log2(n_distinct) if distribution is uniform
        if n_distinct > 1:
            bits_per_sym = (n_distinct - 1).bit_length()
            print(f"[SPECULATION] Could be ~{bits_per_sym} bits per symbol if encoding uses all types equally.")
            bits = len(zwc_sequence) * bits_per_sym
            print(f"[SPECULATION] Potential raw payload: ~{bits} bits = ~{bits // 8} bytes")

    # Position analysis
    positions = [i for i, ch in enumerate(text) if ch in ZWC_CHARS]
    if len(positions) > 1:
        gaps = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
        avg_gap = sum(gaps) / len(gaps)
        print(f"\nPosition Analysis:")
        print(f"  First ZWC at position : {positions[0]}")
        print(f"  Last ZWC at position  : {positions[-1]}")
        print(f"  Average gap between ZWCs : {avg_gap:.1f} characters")
        if avg_gap > 5:
            print("  [INFERENCE] Sparse insertion - consistent with word-boundary placement")
        else:
            print("  [INFERENCE] Dense insertion - possibly block embedding")

        # Gap histogram (dynamic)
        print("\nGap distribution (first 10 most common gaps):")
        gap_counter = Counter(gaps)
        for gap, cnt in gap_counter.most_common(10):
            print(f"    Gap = {gap:3d} chars : {cnt} occurrences")


# ──────────────────────────────────────────────────────────────────
# PASSIVE ATTACK 3: Blind Bit Extraction
# ──────────────────────────────────────────────────────────────────
def attack_extract_raw(text: str):
    banner("PASSIVE ATTACK 3 — Blind Raw Bit Extraction (Adaptive 1-bit Mapping)")

    # 1. Dynamically count frequencies of ZWCs in text
    zwc_in_text = [ch for ch in text if ch in ZWC_CHARS]
    freq = Counter(zwc_in_text)

    if len(freq) < 2:
        print("[INFO] Less than 2 distinct ZWC types found. Standard 1-bit decryption is not possible.")
        # Fallback: check if any default baseline characters exist
        zwc_seq = [ch for ch in text if ch in (ORIG_ZWC_0, ORIG_ZWC_1)]
        if not zwc_seq:
            return
        top_2 = [ORIG_ZWC_0, ORIG_ZWC_1]
        print("[INFO] Falling back to default baseline ZWCs (U+200B, U+200C).")
    else:
        # Retrieve the 2 most frequent ZWCs as candidate 0 and 1
        top_2 = [item[0] for item in freq.most_common(2)]
        print(f"[INFO] Blind analysis detected the 2 most frequent ZWC symbols:")
        print(f"       Symbol A: U+{ord(top_2[0]):04X} (Frequency: {freq[top_2[0]]})")
        print(f"       Symbol B: U+{ord(top_2[1]):04X} (Frequency: {freq[top_2[1]]})")
        # Dynamic hint if frequencies are extremely imbalanced
        if freq[top_2[0]] > 2 * freq[top_2[1]]:
            print("[HINT]   Significant frequency imbalance — either the message is heavily skewed or these are not the correct 0/1 pair.")

    zwc_a, zwc_b = top_2[0], top_2[1]
    # Filter sequence to contain only these two characters
    zwc_seq = [ch for ch in zwc_in_text if ch in (zwc_a, zwc_b)]

    # 2. Blind permutation testing: test [A=0, B=1] and [A=1, B=0]
    trials = [
        (zwc_a, zwc_b, f"Mapping Scheme 1 (U+{ord(zwc_a):04X}=0, U+{ord(zwc_b):04X}=1)"),
        (zwc_b, zwc_a, f"Mapping Scheme 2 (U+{ord(zwc_b):04X}=0, U+{ord(zwc_a):04X}=1)")
    ]

    success = False
    for z0, z1, label in trials:
        bits = ''.join('0' if ch == z0 else '1' for ch in zwc_seq)

        # Convert to byte stream
        message_bytes = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = int(bits[i:i + 8], 2)
            if byte_val == 0xFF:  # Use original 0xFF terminator logic
                break
            message_bytes.append(byte_val)

        try:
            # Core blind attack verification via UTF-8 decoding check
            raw_msg = bytes(message_bytes).decode('utf-8')
            print(f"\n[SUCCESS] Valid mapping captured! -> {label}")
            print(f"Total bits extracted: {len(bits)} bits")
            print(f"[RESULT] Successfully decrypted plaintext blindly: '{raw_msg}'")
            print("[VERDICT] Steganography algorithm broken blindly (no hardcoded baseline required).")
            success = True
            break  # Exit early upon successful decryption
        except Exception:
            # Decoding failed implies wrong mapping direction, proceed to the next scheme
            continue

    # 3. If both schemes fail UTF-8 decoding, payload might be encrypted or corrupted
    if not success:
        print("\n[RESULT] Attempted all binary mapping permutations, but failed to restore standard UTF-8 text.")
        print("[INFERENCE] Possible reasons: 1. Hidden payload is encrypted (e.g., AES used); 2. Multi-bit (2-bit) encoding used; 3. Data corruption.")
        print("[HINT] Please use 'stats' to observe features, or use 'brute' module to brute-force the key.")
        # Additional dynamic analysis: show first 100 bits as hex preview
        bits = ''.join('0' if ch == zwc_a else '1' for ch in zwc_seq)
        if bits:
            print("\n[DEBUG] Raw bits (first 128) assuming first mapping:")
            print(f"       {bits[:128]}")
            print("[DEBUG] If the data is encrypted, no plaintext will appear.")


# ──────────────────────────────────────────────────────────────────
# PASSIVE ATTACK 4: Known-Key Decoder (Adaptive 2-bit Blind Mapping)
# ──────────────────────────────────────────────────────────────────
def decode_enhanced_with_key(text: str, passkey: str) -> str:
    """Try to decode enhanced stego text with a given passkey using blind symbol detection."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        AES_AVAIL = True
    except ImportError:
        AES_AVAIL = False

    def derive_perm(pk):
        import random as rnd
        seed = int(hashlib.sha256(('perm:' + pk).encode()).hexdigest(), 16)
        r = rnd.Random(seed)
        p = list(range(4))
        r.shuffle(p)
        return p

    perm = derive_perm(passkey)
    inv_perm = [0] * 4
    for i, p in enumerate(perm):
        inv_perm[p] = i

    # Blind upgrade: Dynamically capture the 4 most frequent ZWCs instead of checking fixed ENH_ZWC_SYMBOLS.
    # This ensures the algorithm works even if the stego characters are changed, as long as there are 4 types.
    freq = Counter([ch for ch in text if ch in ZWC_CHARS])
    if len(freq) >= 4:
        active_symbols = [item[0] for item in freq.most_common(4)]
        active_symbols.sort()  # Sort by code point to ensure consistency of permutation index
        print(f"[DYNAMIC] Using top-4 ZWCs from text: {[hex(ord(s)) for s in active_symbols]}")
    else:
        active_symbols = ENH_ZWC_SYMBOLS
        print(f"[DYNAMIC] Less than 4 ZWC types found. Falling back to default symbols.")

    zwc_seq = [ch for ch in text if ch in active_symbols]
    if not zwc_seq:
        return '[ERROR] No suitable ZWC characters found for 2-bit decoding.'

    nibbles = []
    for ch in zwc_seq:
        idx = active_symbols.index(ch)
        nibbles.append(inv_perm[idx])

    raw = []
    for i in range(0, len(nibbles) - 3, 4):
        b = (nibbles[i] << 6) | (nibbles[i + 1] << 4) | (nibbles[i + 2] << 2) | nibbles[i + 3]
        raw.append(b)
    raw = bytes(raw)

    if len(raw) < 4:
        return '[ERROR] Payload too short.'

    ct_len = struct.unpack('>I', raw[:4])[0]
    ciphertext = raw[4:4 + ct_len]
    stored_tag = raw[4 + ct_len:4 + ct_len + 32]

    # HMAC check
    hmac_key = hashlib.sha256(('hmac:' + passkey).encode()).digest()
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
        kb = hashlib.sha256(passkey.encode()).digest() * ((len(ciphertext) // 32) + 1)
        return bytes(a ^ b for a, b in zip(ciphertext, kb[:len(ciphertext)])).decode('utf-8', errors='replace')


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
    # Dynamic noise: prefer ZWCs that are NOT currently present in the text, to maximize confusion
    present_zwcs = set(ch for ch in text if ch in ZWC_CHARS)
    potential_noise = list(ZWC_CHARS - present_zwcs) if (ZWC_CHARS - present_zwcs) else list(ZWC_CHARS)
    noise_symbols = potential_noise

    chars = list(text)
    injected = 0
    result = []
    for ch in chars:
        result.append(ch)
        if ch == ' ' and rng.random() < density:
            result.append(rng.choice(noise_symbols))
            injected += 1

    noisy = ''.join(result)
    original_zwc_count = sum(1 for c in text if c in ZWC_CHARS)
    print(f"Original ZWC count : {original_zwc_count}")
    print(f"Noise ZWC injected : {injected}")
    print(f"Total ZWC now      : {sum(1 for c in noisy if c in ZWC_CHARS)}")
    print("[RESULT] Noise injected. Original message bits corrupted.")
    print("[RESULT] Extraction will produce garbled output. HMAC will FAIL on enhanced version.")
    # Dynamic feedback: show which noise characters were used
    used_noise = set(ch for ch in noisy if ch in ZWC_CHARS) - present_zwcs
    if used_noise:
        print(f"[DYNAMIC] Injected noise characters: {[hex(ord(c)) for c in used_noise]}")
    return noisy


# ──────────────────────────────────────────────────────────────────
# ACTIVE ATTACK 7: ZWC Substitution Attack (Fully Blind Interception)
# ──────────────────────────────────────────────────────────────────
def attack_substitute(text: str) -> str:
    banner("ACTIVE ATTACK 7 — Blind ZWC Substitution Attack")

    # Blind Upgrade: Dynamically detect which ZWCs are currently being used for steganography
    present_zwcs = set(ch for ch in text if ch in ZWC_CHARS)
    if not present_zwcs:
        print("[RESULT] No active ZWC characters found to substitute.")
        return text

    # Pick ZWCs NOT used in the current text from the full set to act as active substitute distractors
    unused_zwcs = list(ZWC_CHARS - present_zwcs)
    if not unused_zwcs:
        # Defensive fallback: if all ZWCs are used, use the full shuffled set
        unused_zwcs = list(ZWC_CHARS)
        print("[DYNAMIC] All known ZWCs are already present. Fallback to full set for substitution.")
    else:
        print(f"[DYNAMIC] Substituting with previously absent ZWCs: {[hex(ord(c)) for c in unused_zwcs[:5]]}...")

    substituted = 0
    result = []
    # To add extra confusion, we can use a random mapping from each original ZWC to a random unused ZWC
    # For better scrambling, we create a substitution dictionary
    substitution_map = {}
    for ch in present_zwcs:
        substitution_map[ch] = random.choice(unused_zwcs)

    for ch in text:
        if ch in present_zwcs:
            result.append(substitution_map[ch])
            substituted += 1
        else:
            result.append(ch)

    print(f"ZWC chars blindly substituted: {substituted}")
    print("[RESULT] All active ZWC symbols mapped to alternative hidden characters.")
    print("[RESULT] Bit streams scrambled blindly without knowing the original mapping.")
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
        # decode_enhanced_with_key already prints dynamic info when called, but we suppress its prints?
        # Actually it prints via its own prints. To avoid cluttering, we redirect? No, we keep as is.
        # For brute-force, we don't want to flood the output with each attempt's internal prints.
        # So we temporarily override sys.stdout? That's complex. Instead we capture the function's output
        # in the caller (UI) using capture_print_output. That's fine.
        if not result.startswith('[FAIL]') and not result.startswith('[ERROR]'):
            print(f"[!!] PASSKEY FOUND: '{key}'")
            print(f"[!!] Decoded message: {result}")
            found = True
            break
        if i % 10 == 0:
            print(f"     Tried {i + 1}/{len(candidates)} keys...", end='\r')

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

    def add_file(p):
        p.add_argument('--file', required=True, help='Input text file')

    def add_out(p):
        p.add_argument('--output', required=True, help='Output text file')

    p_scan = sub.add_parser('scan', help='Detect ZWC characters')
    p_stats = sub.add_parser('stats', help='Statistical analysis')
    p_ext = sub.add_parser('extract', help='Raw bit extraction')
    p_strip = sub.add_parser('strip', help='Strip all ZWC chars')
    p_noise = sub.add_parser('noise', help='Inject random ZWC noise')
    p_sub = sub.add_parser('subst', help='ZWC substitution attack')
    p_brute = sub.add_parser('brute', help='Passkey brute-force')
    p_full = sub.add_parser('fullscan', help='Run all passive attacks')
    p_known = sub.add_parser('decode', help='Decode with known passkey')

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

    if args.cmd == 'scan':
        attack_scan(text)
    elif args.cmd == 'stats':
        attack_stats(text)
    elif args.cmd == 'extract':
        attack_extract_raw(text)
    elif args.cmd == 'fullscan':
        attack_fullscan(text)
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