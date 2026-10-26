#!/usr/bin/env python3
"""Offline, hash-pinned D110_M 4.31 factory-reset history patch builder.

Never opens a printer connection. Requires the original *headered* d110m.bin.
The application remains version 4.31; --transport-version changes only its
update-container version, if needed by a particular updater's version gate.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from zlib import crc32

APP_SHA256 = '334260a24c516507386bd6cf99b7735bffb12a200b2354070c1878b627181e84'
BASE = 0x01010000
CALL_OFFSET = 0x7388
SAVE_OFFSET = 0x12e20
ZERO_OFFSET = 0x182
APP_SIZE = 0x1c724
MODEL_ID = 2320


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encode_bl(source, target):
    """Encode ARM Thumb BL T1, independently decoded in verification."""
    delta = target - (source + 4)
    if delta & 1 or not -(1 << 24) <= delta < (1 << 24):
        raise ValueError('Unaligned or out-of-range Thumb BL')
    immediate = delta & 0x1ffffff
    sign = immediate >> 24
    i1, i2 = (immediate >> 23) & 1, (immediate >> 22) & 1
    j1, j2 = 1 ^ i1 ^ sign, 1 ^ i2 ^ sign
    return struct.pack('<HH', 0xf000 | sign << 10 | (immediate >> 12) & 0x3ff,
                       0xd000 | j1 << 13 | j2 << 11 | (immediate >> 1) & 0x7ff)


def validate_container(image):
    if len(image) < 28 or image[0] != 0x18:
        raise ValueError('Expected a headered NIIMBOT firmware .bin, not an app-only image')
    header = bytearray(image[:24])
    header[1:4] = bytes(3)
    length, checksum = struct.unpack_from('<II', image, 4)
    if length != len(image) - 28 or crc32(image[28:]) != checksum:
        raise ValueError('Firmware payload size/CRC mismatch')
    if crc32(header) != struct.unpack_from('<I', image, 24)[0]:
        raise ValueError('Firmware header CRC mismatch')
    return struct.unpack_from('<HH', image, 20)


def build(image, transport_version=431):
    version, model = validate_container(image)
    original = image[28:]
    if model != MODEL_ID or version != 431 or len(original) != APP_SIZE or sha256(original) != APP_SHA256:
        raise ValueError('Only the exact original D110_M 4.31 image is supported')
    if not 431 <= transport_version < 500:
        raise ValueError('Transport version must remain in 4.31..4.99')
    expected = encode_bl(BASE + CALL_OFFSET, BASE + SAVE_OFFSET)
    if original[CALL_OFFSET:CALL_OFFSET+4] != expected:
        raise ValueError('Original save call does not match')

    # This wrapper is appended after all original code/data. No code cave or
    # linker relocation is assumed. It stays in the original last 256-byte page.
    # r0 is the settings pointer provided by the original handler.
    stub = bytearray.fromhex('10 b5 04 46 28 30 f4 21')
    # push {r4,lr}; mov r4,r0; adds r0,#0x28; movs r1,#0xf4
    stub += encode_bl(BASE + APP_SIZE + len(stub), BASE + ZERO_OFFSET)
    stub += bytes.fromhex('20 46')                       # mov r0,r4
    stub += encode_bl(BASE + APP_SIZE + len(stub), BASE + SAVE_OFFSET)
    stub += bytes.fromhex('10 bd')                       # pop {r4,pc}
    if len(stub) != 20:
        raise AssertionError('Unexpected stub length')
    patched = bytearray(original)
    patched[CALL_OFFSET:CALL_OFFSET+4] = encode_bl(BASE + CALL_OFFSET, BASE + APP_SIZE)
    patched += stub
    if (len(patched)-1)//256 != (len(original)-1)//256:
        raise AssertionError('Patch unexpectedly needs an additional flash page')

    header = bytearray(image[:28])
    struct.pack_into('<II', header, 4, len(patched), crc32(patched))
    struct.pack_into('<H', header, 20, transport_version)
    normalized = bytearray(header[:24]); normalized[1:4] = bytes(3)
    struct.pack_into('<I', header, 24, crc32(normalized))
    result = bytes(header + patched)
    validate_container(result)
    manifest = {
        'status': 'Experimental build; see separate offline and hardware verification reports.',
        'model': 'D110_M', 'model_id': MODEL_ID,
        'base_firmware': '4.31', 'reported_firmware_after_patch': '4.31',
        'update_container_version': f'{transport_version//100}.{transport_version%100:02d}',
        'original_app_sha256': APP_SHA256, 'original_container_sha256': sha256(image),
        'patched_app_sha256': sha256(patched), 'patched_container_sha256': sha256(result),
        'original_app_bytes': len(original), 'patched_app_bytes': len(patched),
        'call_offset_in_app': hex(CALL_OFFSET), 'call_offset_in_container': hex(CALL_OFFSET+28),
        'original_call_hex': expected.hex(), 'patched_call_hex': patched[CALL_OFFSET:CALL_OFFSET+4].hex(),
        'wrapper_offset_in_app': hex(APP_SIZE), 'wrapper_hex': stub.hex(),
        'cleared_ram': {'address': '0x00020928', 'length': 244},
        'settings_flash_address': '0x010ff000',
        'usage': 'Remove roll, factory reset, power off/on, then insert the zero-counter sticker/refill.',
    }
    return result, bytes(patched), manifest


def parse_version(value):
    pieces = value.split('.')
    if len(pieces) != 2 or not all(p.isdigit() for p in pieces) or len(pieces[1]) != 2:
        raise argparse.ArgumentTypeError('Use a version such as 4.31')
    return int(pieces[0])*100 + int(pieces[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('--output-dir', type=Path, default=Path('build'))
    parser.add_argument('--transport-version', type=parse_version, default=431)
    args = parser.parse_args()
    original = args.original.read_bytes()
    result, app, manifest = build(original, args.transport_version)
    version = manifest['update_container_version']
    args.output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        f'D110_M_V{version}_history-reset.bin': result,
        'D110_M_V4.31_original.bin': original,
        'patched-app-analysis-only.bin': app,
        'patch-manifest.json': (json.dumps(manifest, indent=2)+'\n').encode(),
    }
    for name, data in files.items():
        target = args.output_dir/name
        if target.exists() and target.read_bytes() != data:
            raise FileExistsError(f'Refusing to overwrite different output: {target}')
    for name, data in files.items():
        (args.output_dir/name).write_bytes(data)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
