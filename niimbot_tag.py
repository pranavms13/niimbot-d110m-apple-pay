#!/usr/bin/env python3
"""Offline D110_M tag inspector and command generator; never connects/writes NFC."""
import argparse
import json
import struct
import zlib
from pathlib import Path

KEY = (0x0000CCA1, 0x000072B7, 0x00006758, 0x000065C9)
MASK = 0xffffffff
DELTA = 0x9e3779b9
PASSWORD = bytes.fromhex('12345678')

def encrypt(block):
    a, b = struct.unpack('<2I', block)
    s = 0
    for _ in range(32):
        s = (s + DELTA) & MASK
        a = (a + (((b << 4) + KEY[0]) ^ (b + s) ^ ((b >> 5) + KEY[1]))) & MASK
        b = (b + (((a << 4) + KEY[2]) ^ (a + s) ^ ((a >> 5) + KEY[3]))) & MASK
    return struct.pack('<2I', a, b)

def decrypt(block):
    a, b = struct.unpack('<2I', block)
    s = 0xc6ef3720
    for _ in range(32):
        b = (b - (((a << 4) + KEY[2]) ^ (a + s) ^ ((a >> 5) + KEY[3]))) & MASK
        a = (a - (((b << 4) + KEY[0]) ^ (b + s) ^ ((b >> 5) + KEY[1]))) & MASK
        s = (s - DELTA) & MASK
    return struct.pack('<2I', a, b)

def counter_block(reserved, used):
    head = struct.pack('<HH', reserved, used)
    return encrypt(head + struct.pack('<I', zlib.crc32(head)))

def inspect_block(raw):
    if len(raw) != 8:
        raise ValueError('Counter ciphertext must be exactly 8 bytes (pages 5 and 6).')
    plain = decrypt(raw)
    reserved, used, crc = struct.unpack('<HHI', plain)
    if crc != zlib.crc32(plain[:4]):
        raise ValueError('Counter CRC mismatch: wrong key/tag format, damaged counter, or wrong dump offset. No write commands generated.')
    return {'reserved': reserved, 'used': used, 'plaintext': plain.hex()}

def hexline(raw):
    return raw.hex(' ').upper()

def make_plan(raw, used):
    old = inspect_block(raw)
    new = counter_block(old['reserved'], used)
    return {
        'old': old,
        'new_used': used,
        'auth': hexline(b'\x1b' + PASSWORD),
        'expected_pack': '55 55',
        'backup_pages_05_06': hexline(raw),
        'writes': [hexline(bytes([0xa2, 5+i])+new[i*4:i*4+4]) for i in range(2)],
        'verify_read': '30 05',
        'expected_first_8_bytes': hexline(new),
        'nfc_tools_batch': ','.join(chunk.hex(':').upper() for chunk in [b'\x1b'+PASSWORD, bytes([0xa2,5])+new[:4], bytes([0xa2,6])+new[4:], b'\x30\x05']),
        'restore_writes': [hexline(bytes([0xa2, 5+i])+raw[i*4:i*4+4]) for i in range(2)],
        'warning': 'This resets tag storage only. D110_M keeps a persistent 20-roll maximum-usage cache and may restore the old count. Stock factory reset does not clear that cache. The patched factory reset in this repository clears it; remove the roll and power-cycle before reinserting the reset tag.',
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_mutually_exclusive_group(required=True)
    s.add_argument('--counter-hex', help='Exactly 8 ciphertext bytes from pages 05 and 06')
    s.add_argument('--dump', type=Path, help='Raw binary dump beginning at page 0, at least 140 bytes; not a BLE RFID response')
    p.add_argument('--used', type=int, default=0, help='Target used count (default 0)')
    args = p.parse_args()
    if not 0 <= args.used <= 65535:
        p.error('--used must be 0..65535')
    try:
        if args.dump:
            dump = args.dump.read_bytes()
            if len(dump) < 140:
                raise ValueError('Need a raw dump starting at page 0 with pages 0..34 (140 bytes).')
            raw = dump[20:28]
            region = b''.join(decrypt(dump[i:i+8]) for i in range(20, 140, 8))
            if zlib.crc32(region[8:116]) != struct.unpack_from('<I', region, 116)[0]:
                raise ValueError('Metadata CRC mismatch: cannot confirm this tag format.')
            plan = make_plan(raw, args.used)
            plan['tag'] = {'uid': (dump[:3]+dump[4:8]).hex(), 'firmware_limit': struct.unpack_from('<H', region, 0x42)[0], 'embedded_identifier': region[8:16].hex(), 'serial': region[16:32].split(b'\0')[0].decode('ascii', errors='replace')}
        else:
            plan = make_plan(bytes.fromhex(args.counter_hex), args.used)
        print(json.dumps(plan, indent=2))
    except (ValueError, OSError) as e:
        p.error(str(e))

if __name__ == '__main__':
    main()
