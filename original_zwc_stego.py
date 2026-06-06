#!/usr/bin/env python3
"""
original_zwc_stego.py
=====================
ORIGINAL Zero-Width Character (ZWC) Text Steganography
Baseline technique based on:
  Bashir et al. (2020), "A High Capacity Text Steganography Utilizing
  Unicode Zero-Width Characters," IEEE ICCIT 2020.

Technique:
  - Converts secret message to binary
  - Maps binary bits to two ZWC symbols:
      '0' -> U+200B (Zero Width Space)
      '1' -> U+200C (Zero Width Non-Joiner)
  - Inserts ZWC pairs after every word/space in the cover text

Usage:
  python3 original_zwc_stego.py embed  --cover cover.txt --secret "Hello" --output stego.txt
  python3 original_zwc_stego.py extract --stego stego.txt
"""

import argparse
import sys
import os

# Zero-Width Characters used
ZWC_0 = '\u200B'   # Zero Width Space      -> represents binary '0'
ZWC_1 = '\u200C'   # Zero Width Non-Joiner -> represents binary '1'
SEPARATOR = '\u200D'  # Zero Width Joiner   -> byte boundary marker

def text_to_binary(text: str) -> str:
    """Convert text string to binary string (8 bits per character, UTF-8)."""
    bits = ''
    for byte in text.encode('utf-8'):
        bits += format(byte, '08b')
    return bits

def binary_to_text(bits: str) -> str:
    """Convert binary string back to text."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(int(byte, 2))
    return bytes(chars).decode('utf-8', errors='replace')

def bits_to_zwc(bits: str) -> str:
    """Convert binary string to ZWC string."""
    zwc_str = ''
    for b in bits:
        zwc_str += ZWC_0 if b == '0' else ZWC_1
    return zwc_str

def zwc_to_bits(zwc_str: str) -> str:
    """Extract bits from ZWC string."""
    bits = ''
    for ch in zwc_str:
        if ch == ZWC_0:
            bits += '0'
        elif ch == ZWC_1:
            bits += '1'
    return bits

def embed(cover_text: str, secret_message: str) -> str:
    """
    Embed secret message into cover text using ZWC.
    Strategy: Distribute ZWC bits after word boundaries.
    """
    binary_payload = text_to_binary(secret_message)
    # Add SEPARATOR as end-of-message marker (one extra byte 0xFF)
    binary_payload += '11111111'  # 0xFF as sentinel byte
    
    zwc_payload = bits_to_zwc(binary_payload)
    
    words = cover_text.split(' ')
    payload_idx = 0
    result_parts = []
    bits_per_word = 1  # Insert 1 ZWC per word space

    for i, word in enumerate(words):
        result_parts.append(word)
        if i < len(words) - 1:  # Don't add after last word
            # Insert ZWC bits after this space
            chunk = ''
            for _ in range(bits_per_word):
                if payload_idx < len(zwc_payload):
                    chunk += zwc_payload[payload_idx]
                    payload_idx += 1
            result_parts.append(chunk + ' ')
    
    stego_text = ''.join(result_parts)
    
    if payload_idx < len(zwc_payload):
        print(f"[WARNING] Cover text too short! Only embedded {payload_idx}/{len(zwc_payload)} bits.")
        print(f"          Need at least {len(zwc_payload)} word-spaces. Try a longer cover text.")
    else:
        print(f"[INFO] Successfully embedded {len(secret_message)} chars ({len(binary_payload)} bits).")
    
    return stego_text

def extract(stego_text: str) -> str:
    """Extract secret message from stego text."""
    zwc_collected = ''
    for ch in stego_text:
        if ch in (ZWC_0, ZWC_1):
            zwc_collected += ch

    bits = zwc_to_bits(zwc_collected)
    
    # Find sentinel 0xFF byte to stop decoding
    message_bytes = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = int(bits[i:i+8], 2)
        if byte_val == 0xFF:
            break
        message_bytes.append(byte_val)
    
    try:
        message = bytes(message_bytes).decode('utf-8', errors='replace')
    except Exception:
        message = '<Extraction failed>'
    
    return message

def main():
    parser = argparse.ArgumentParser(description='Original ZWC Text Steganography Tool')
    subparsers = parser.add_subparsers(dest='command')

    # Embed subcommand
    embed_parser = subparsers.add_parser('embed', help='Embed secret message into cover text')
    embed_parser.add_argument('--cover', required=True, help='Path to cover text file')
    embed_parser.add_argument('--secret', required=True, help='Secret message string to embed')
    embed_parser.add_argument('--output', required=True, help='Output stego text file')

    # Extract subcommand
    extract_parser = subparsers.add_parser('extract', help='Extract hidden message from stego text')
    extract_parser.add_argument('--stego', required=True, help='Path to stego text file')

    args = parser.parse_args()

    if args.command == 'embed':
        if not os.path.exists(args.cover):
            print(f"[ERROR] Cover file not found: {args.cover}")
            sys.exit(1)
        with open(args.cover, 'r', encoding='utf-8') as f:
            cover_text = f.read()
        stego = embed(cover_text, args.secret)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(stego)
        print(f"[INFO] Stego text saved to: {args.output}")
        print(f"[INFO] Visible character count: {len([c for c in stego if not c in [ZWC_0, ZWC_1, SEPARATOR]])}")

    elif args.command == 'extract':
        if not os.path.exists(args.stego):
            print(f"[ERROR] Stego file not found: {args.stego}")
            sys.exit(1)
        with open(args.stego, 'r', encoding='utf-8') as f:
            stego_text = f.read()
        message = extract(stego_text)
        print(f"[RESULT] Extracted message: {message}")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
