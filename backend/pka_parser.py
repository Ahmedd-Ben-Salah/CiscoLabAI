"""
pka_parser.py - Decode/Encode Cisco Packet Tracer .pka/.pkt files

Supports both old formats (XOR + zlib) and new PT 8.x formats (XOR + Twofish EAX + XOR + zlib).
Based on reverse engineering by axcheron (ptexplorer) and mircodz (pka2xml).
"""

import zlib
import os
import struct
import re
from twofish import Twofish

# --- Helper functions for Twofish EAX ---

def _xor_block(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def _dbl(L):
    val = int.from_bytes(L, 'big')
    msb = val >> 127
    val = ((val << 1) & ((1 << 128) - 1))
    if msb:
        val ^= 0x87
    return val.to_bytes(16, 'big')

def _cmac(cipher, msg, t):
    K = cipher.encrypt(b'\x00' * 16)
    K1 = _dbl(K)
    K2 = _dbl(K1)
    
    padded_msg = bytes(15) + bytes([t]) + msg
    blocks = [padded_msg[i:i+16] for i in range(0, len(padded_msg), 16)]
    
    if len(blocks[-1]) == 16:
        blocks[-1] = _xor_block(blocks[-1], K1)
    else:
        blocks[-1] = _xor_block(blocks[-1] + b'\x80' + b'\x00' * (15 - len(blocks[-1])), K2)
        
    X = b'\x00' * 16
    for block in blocks:
        X = cipher.encrypt(_xor_block(X, block))
    return X

def _eax_decrypt(cipher, iv, ciphertext_with_tag):
    C = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    n_mac = _cmac(cipher, iv, 0)
    
    # CTR mode decryption
    ctr = bytearray(n_mac)
    plaintext = bytearray()
    
    for i in range(0, len(C), 16):
        block = C[i:i+16]
        pad = cipher.encrypt(bytes(ctr))
        plaintext.extend(_xor_block(block, pad[:len(block)]))
        for j in range(15, -1, -1):
            ctr[j] = (ctr[j] + 1) & 0xFF
            if ctr[j] != 0:
                break
                
    return bytes(plaintext)


def _eax_encrypt(cipher, iv, plaintext):
    n_mac = _cmac(cipher, iv, 0)
    h_mac = _cmac(cipher, b'', 1)
    
    # CTR mode encryption
    ctr = bytearray(n_mac)
    ciphertext = bytearray()
    
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        pad = cipher.encrypt(bytes(ctr))
        ciphertext.extend(_xor_block(block, pad[:len(block)]))
        
        for j in range(15, -1, -1):
            ctr[j] = (ctr[j] + 1) & 0xFF
            if ctr[j] != 0:
                break
                
    C = bytes(ciphertext)
    c_mac = _cmac(cipher, C, 2)
    tag = _xor_block(_xor_block(n_mac, h_mac), c_mac)
    
    return C + tag

# --- Core Crypto Logic ---

def is_old_pt(decrypted_first_stage):
    """Check if the PKA uses the older XOR-only format (usually PT7 and older)."""
    # Verify if bytes 4-5 or 5-6 match the zlib magic headers \x78\x9C, etc.
    if len(decrypted_first_stage) < 6:
        return True
    return decrypted_first_stage[4] == 0x78 or decrypted_first_stage[5] == 0x78

def _decrypt_stage1(encrypted_data):
    """Common stage 1 XOR: b[i] = a[length + ~i] ^ (length - i * length)"""
    length = len(encrypted_data)
    processed = bytearray(length)
    for i in range(length):
        processed[i] = encrypted_data[length + ~i] ^ ((length - i * length) & 0xFF)
    return bytes(processed)

def _encrypt_stage4(encrypted_twofish):
    """Common stage 4 XOR (encryption reverse of stage 1).
    Equivalent to: output[length + ~i] = input[i] ^ (length - i * length)
    """
    length = len(encrypted_twofish)
    output = bytearray(length)
    for i in range(length):
        output[length + ~i] = encrypted_twofish[i] ^ ((length - i * length) & 0xFF)
    return bytes(output)

# --- Public API ---

def decode_pka_bytes(file_bytes):
    """Decode from bytes (for in-memory processing)."""
    if len(file_bytes) < 10:
        raise ValueError("File too small")
    
    # Stage 1 - First Deobfuscation
    stage1 = _decrypt_stage1(file_bytes)
    
    if is_old_pt(stage1):
        # OLD FORMAT: Just direct XOR with descending file size
        file_size = len(file_bytes)
        decrypted = bytearray()
        xor_key = file_size
        for byte in file_bytes:
            decrypted.append((byte ^ xor_key) & 0xFF)
            xor_key -= 1
        stage3_out = decrypted
    else:
        # NEW FORMAT (PT8+): Twofish EAX
        key = bytes([137] * 16)
        iv = bytes([16] * 16)
        cipher = Twofish(key)
        
        # Stage 2 - Twofish EAX Decryption
        stage2 = _eax_decrypt(cipher, iv, stage1)
        
        # Stage 3 - Second Deobfuscation: b[i] = a[i] ^ (length - i)
        out_length = len(stage2)
        stage3 = bytearray(out_length)
        for i in range(out_length):
            stage3[i] = stage2[i] ^ ((out_length - i) & 0xFF)
        stage3_out = stage3
        
    # Extract uncompressed size and decompress
    # uncompressed_size = int.from_bytes(stage3_out[:4], byteorder='big')
    try:
        xml_bytes = zlib.decompress(stage3_out[4:])
    except zlib.error as e:
        raise ValueError(f"Decompression failed: {e}")
        
    try:
        xml_string = xml_bytes.decode('utf-8')
    except UnicodeDecodeError:
        xml_string = xml_bytes.decode('latin-1')
        
    # Sanitize invalid XML characters (like unescaped control chars)
    _illegal_xml_chars_RE = re.compile(
        '[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1F\\uD800-\\uDFFF\\uFFFE\\uFFFF]'
    )
    return _illegal_xml_chars_RE.sub('', xml_string)


def encode_pka_bytes(xml_string, force_pt8=True):
    """Encode XML string to .pka/.pkt bytes."""
    xml_bytes = xml_string.encode('utf-8') if isinstance(xml_string, str) else xml_string
    uncompressed_size = len(xml_bytes)
    
    # Custom zlib configuration matching PT: Compress without automatic sizing logic tweaking
    compressed = zlib.compress(xml_bytes)
    # The first 4 bytes indicate uncompressed size
    payload = uncompressed_size.to_bytes(4, 'big') + compressed
    
    if not force_pt8:
        # OLD FORMAT encoding
        encrypted = bytearray()
        xor_key = len(payload)
        for byte in payload:
            encrypted.append((byte ^ xor_key) & 0xFF)
            xor_key -= 1
        return bytes(encrypted)
    else:
        # NEW FORMAT (PT8) encoding
        # Stage 2 - Obfuscation: compressed[i] ^ (compressed.size() - i)
        length = len(payload)
        stage2 = bytearray(length)
        for i in range(length):
            stage2[i] = payload[i] ^ ((length - i) & 0xFF)
            
        # Stage 3 - Twofish EAX Encryption
        key = bytes([137] * 16)
        iv = bytes([16] * 16)
        cipher = Twofish(key)
        stage3 = _eax_encrypt(cipher, iv, stage2)
        
        # Stage 4 - Final obfuscation
        final = _encrypt_stage4(stage3)
        return final


def decode_pka(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, 'rb') as f:
        return decode_pka_bytes(f.read())


def encode_pka(xml_string, filepath, force_pt8=True):
    encoded = encode_pka_bytes(xml_string, force_pt8)
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(encoded)
