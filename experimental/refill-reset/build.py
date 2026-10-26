#!/usr/bin/env python3
"""Build an EXPERIMENTAL combined NFC/history reset and reboot extension.

Requires clang with the ARM target. Never connects to a printer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from zlib import crc32

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from patch_firmware import build as build_history, encode_bl, validate_container, BASE


def extract_object(data):
    if data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected a little-endian ELF32 object')
    if struct.unpack_from('<HH', data, 16) != (1, 40):
        raise ValueError('Expected a relocatable ARM object')
    shoff = struct.unpack_from('<I', data, 32)[0]
    shsize, shnum, shnames = struct.unpack_from('<HHH', data, 46)
    sections = [struct.unpack_from('<10I', data, shoff + i*shsize) for i in range(shnum)]
    def body(s): return data[s[4]:s[4]+s[5]]
    names = body(sections[shnames])
    def string(table, offset): return table[offset:].split(b'\0', 1)[0].decode()
    named = {string(names, s[0]): (i, s) for i, s in enumerate(sections)}
    text_index, text_section = named['.text']
    for name, (_, section) in named.items():
        if section[1] in (4, 9) and section[7] == text_index and section[5]:
            raise ValueError(f'Unresolved code relocations: {name}')
        if name.startswith(('.data', '.bss', '.rodata')) and section[5]:
            raise ValueError(f'Unexpected separate data allocation: {name}')
    symtab = named['.symtab'][1]
    strings = body(sections[symtab[6]])
    symbols = {}
    for offset in range(symtab[4], symtab[4]+symtab[5], symtab[9]):
        name, value, size, info, other, index = struct.unpack_from('<IIIBBH', data, offset)
        if index == text_index and info & 15 == 2:
            symbols[string(strings, name)] = {'offset': value & ~1, 'size': size}
    return body(text_section), symbols


def build(output, clang='clang'):
    output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name('refill.c')
    obj = output/'refill.o'
    flags = ['--target=arm-none-eabi', '-mcpu=cortex-m0', '-mthumb', '-Os',
             '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
             '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
             '-fno-jump-tables', '-Wall', '-Wextra', '-Werror']
    subprocess.run([clang, *flags, '-c', str(source), '-o', str(obj)], check=True)
    extension, symbols = extract_object(obj.read_bytes())
    original = (ROOT/'firmware/D110_M_V4.31_original.bin').read_bytes()
    history, _, _ = build_history(original)
    app = bytearray(history[28:])
    extension_offset = (len(app) + 3) & ~3
    app.extend(bytes(extension_offset-len(app)))
    app.extend(extension)
    hooks = []
    for offset, old, symbol in [(0x4eee, 0x4d94, 'refill_dispatch'),
                                 (0x4efc, 0x4dc4, 'refill_send'),
                                 (0xe284, 0xd708, 'refill_startup')]:
        expected = encode_bl(BASE + offset, BASE + old)
        if app[offset:offset+4] != expected:
            raise ValueError(f'Unexpected stock call at {offset:x}')
        target = BASE + extension_offset + symbols[symbol]['offset']
        replacement = encode_bl(BASE + offset, target)
        app[offset:offset+4] = replacement
        hooks.append({'offset': offset, 'original': expected.hex(),
                      'replacement': replacement.hex(), 'target': target, 'symbol': symbol})
    # Stock staging receiver reserves 128 KiB. Keep the complete image inside it.
    if len(app) + 28 >= 0x20000:
        raise ValueError('Candidate exceeds the audited staging capacity')
    header = bytearray(history[:28])
    struct.pack_into('<II', header, 4, len(app), crc32(app))
    normalized = bytearray(header[:24]); normalized[1:4] = bytes(3)
    struct.pack_into('<I', header, 24, crc32(normalized))
    image = bytes(header + app)
    assert validate_container(image) == (431, 2320)
    filename = 'D110_M_V4.31_refill-reset_EXPERIMENTAL.bin'
    digest = hashlib.sha256(image).hexdigest()
    manifest = {'status': 'EXPERIMENTAL: see VALIDATION.md for results tied to an exact image hash',
                'model': 'D110_M', 'version': '4.31',
                'image': filename, 'image_bytes': len(image), 'sha256': digest,
                'extension_offset': extension_offset, 'extension_bytes': len(extension),
                'symbols': symbols, 'hooks': hooks,
                'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'compiler': subprocess.check_output([clang, '--version'], text=True).splitlines()[0],
                'compiler_flags': flags}
    (output/filename).write_bytes(image)
    (output/'refill-extension.bin').write_bytes(extension)
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (output/'SHA256SUMS.txt').write_text(f'{digest}  {filename}\n')
    return image, manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir', type=Path, default=ROOT/'build/refill-reset')
    p.add_argument('--clang', default='clang')
    args = p.parse_args()
    _, manifest = build(args.output_dir, args.clang)
    print(json.dumps(manifest, indent=2))
